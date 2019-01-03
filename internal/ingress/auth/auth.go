package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/kubernetes-sigs/aws-alb-ingress-controller/internal/ingress/annotations/action"
	"github.com/kubernetes-sigs/aws-alb-ingress-controller/internal/ingress/annotations/parser"
	"github.com/kubernetes-sigs/aws-alb-ingress-controller/internal/utils"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

const (
	AnnotationAuthType                     string = "auth-type"
	AnnotationAuthScope                    string = "auth-scope"
	AnnotationAuthSessionCookie            string = "auth-session-cookie"
	AnnotationAuthSessionTimeout           string = "auth-session-timeout"
	AnnotationAuthOnUnauthenticatedRequest string = "auth-on-unauthenticated-request"
	AnnotationAuthIDPCognito               string = "auth-idp-cognito"
	AnnotationAuthIDPOIDC                  string = "auth-idp-oidc"
)

const (
	DefaultAuthType                     = TypeNone
	DefaultAuthScope                    = "openid"
	DefaultAuthSessionCookie            = "AWSELBAuthSessionCookie"
	DefaultAuthSessionTimeout           = 604800
	DefaultAuthOnUnauthenticatedRequest = OnUnauthenticatedRequestAuthenticate
)

// Authentication module interface
type Module interface {
	// Init setup index & watch functionality.
	Init(controller controller.Controller, ingressChan chan<- event.GenericEvent, serviceChan chan<- event.GenericEvent) error

	// NewConfig builds authentication config for ingress & ingressBackend.
	NewConfig(ctx context.Context, ingress *extensions.Ingress, backend extensions.IngressBackend, protocol string) (Config, error)
}

// NewModule constructs new Authentication module
func NewModule(cache cache.Cache) Module {
	return &defaultModule{
		cache: cache,
	}
}

type defaultModule struct {
	cache cache.Cache
}

func (m *defaultModule) NewConfig(ctx context.Context, ingress *extensions.Ingress, backend extensions.IngressBackend, protocol string) (Config, error) {
	if protocol != elbv2.ProtocolEnumHttps {
		return Config{
			Type: TypeNone,
		}, nil
	}

	cfg := Config{
		Type:                     DefaultAuthType,
		OnUnauthenticatedRequest: DefaultAuthOnUnauthenticatedRequest,
		Scope:                    DefaultAuthScope,
		SessionCookie:            DefaultAuthSessionCookie,
		SessionTimeout:           DefaultAuthSessionTimeout,
	}

	ingressAnnos := ingress.Annotations
	var serviceAnnos map[string]string
	if !action.Use(backend.ServicePort.String()) {
		serviceKey := types.NamespacedName{
			Namespace: ingress.Namespace,
			Name:      backend.ServiceName,
		}
		service := corev1.Service{}
		if err := m.cache.Get(ctx, serviceKey, &service); err != nil {
			return Config{}, errors.Wrapf(err, "failed to get service %v", serviceKey)
		}
		serviceAnnos = service.Annotations
	}
	_ = LoadStringAnnotation(AnnotationAuthType, (*string)(&cfg.Type), serviceAnnos, ingressAnnos)
	_ = LoadStringAnnotation(AnnotationAuthOnUnauthenticatedRequest, (*string)(&cfg.OnUnauthenticatedRequest), serviceAnnos, ingressAnnos)
	_ = LoadStringAnnotation(AnnotationAuthScope, &cfg.Scope, serviceAnnos, ingressAnnos)
	_ = LoadStringAnnotation(AnnotationAuthSessionCookie, &cfg.SessionCookie, serviceAnnos, ingressAnnos)
	if _, err := LoadInt64Annotation(AnnotationAuthSessionTimeout, &cfg.SessionTimeout, serviceAnnos, ingressAnnos); err != nil {
		return Config{}, err
	}

	switch cfg.Type {
	case TypeCognito:
		{
			exists, err := LoadJSONAnnotation(AnnotationAuthIDPCognito, &cfg.IDPCognito, serviceAnnos, ingressAnnos)
			if err != nil {
				return Config{}, err
			}
			if !exists {
				return Config{}, errors.New(fmt.Sprintf("annotation %s is required when authType == %s", AnnotationAuthIDPCognito, TypeCognito))
			}
		}
	case TypeOIDC:
		{
			exists, err := m.loadIDPOIDC(ctx, &cfg.IDPOIDC, ingress.Namespace, serviceAnnos, ingressAnnos)
			if err != nil {
				return Config{}, err
			}
			if !exists {
				return Config{}, errors.New(fmt.Sprintf("annotation %s is required when authType == %s", AnnotationAuthIDPOIDC, TypeOIDC))
			}
		}
	}

	return cfg, nil
}

func (m *defaultModule) loadIDPOIDC(ctx context.Context, idpOIDC *IDPOIDC, namespace string, serviceAnnos map[string]string, ingressAnnos map[string]string) (bool, error) {
	annoIDPOIDC := AnnotationSchemaIDPOIDC{}
	exists, err := LoadJSONAnnotation(AnnotationAuthIDPOIDC, &annoIDPOIDC, serviceAnnos, ingressAnnos)
	if err != nil {
		return true, errors.Wrapf(err, "failed to load configuration for IDP OIDC")
	}
	if !exists {
		return false, nil
	}

	clientId := annoIDPOIDC.ClientId
	clientSecret := annoIDPOIDC.ClientSecret
	if annoIDPOIDC.SecretName != "" {
		secretKey := types.NamespacedName{
			Namespace: namespace,
			Name:      annoIDPOIDC.SecretName,
		}
		k8sSecret := corev1.Secret{}
		if err := m.cache.Get(ctx, secretKey, &k8sSecret); err != nil {
			return true, errors.Wrapf(err, "failed to load k8s secret: %v", secretKey)
		}
		clientId = string(k8sSecret.Data["clientId"])
		clientSecret = string(k8sSecret.Data["clientSecret"])
	}

	*idpOIDC = IDPOIDC{
		Issuer:                annoIDPOIDC.Issuer,
		AuthorizationEndpoint: annoIDPOIDC.AuthorizationEndpoint,
		TokenEndpoint:         annoIDPOIDC.TokenEndpoint,
		UserInfoEndpoint:      annoIDPOIDC.UserInfoEndpoint,
		ClientId:              clientId,
		ClientSecret:          clientSecret,
	}
	return true, nil
}

// TODO: move these LoadAnnotations utility into annotations package :D
// LoadStringAnnotation loads annotation into value of type string from list of annotations by priority.
func LoadStringAnnotation(annotation string, value *string, annotations ...map[string]string) bool {
	key := parser.GetAnnotationWithPrefix(annotation)
	raw, ok := utils.MapFindFirst(key, annotations...)
	if !ok {
		return false
	}
	*value = raw
	return true
}

// LoadInt64Annotation loads annotation into value of type int64 from list of annotations by priority.
func LoadInt64Annotation(annotation string, value *int64, annotations ...map[string]string) (bool, error) {
	key := parser.GetAnnotationWithPrefix(annotation)
	raw, ok := utils.MapFindFirst(key, annotations...)
	if !ok {
		return false, nil
	}
	i, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return true, errors.Wrapf(err, "failed to parse annotation, %v: %v", key, raw)
	}
	*value = i
	return true, nil
}

// LoadInt64Annotation loads annotation into value of type JSON from list of annotations by priority.
func LoadJSONAnnotation(annotation string, value interface{}, annotations ...map[string]string) (bool, error) {
	key := parser.GetAnnotationWithPrefix(annotation)
	raw, ok := utils.MapFindFirst(key, annotations...)
	if !ok {
		return false, nil
	}
	if err := json.Unmarshal([]byte(raw), value); err != nil {
		return true, errors.Wrapf(err, "failed to parse annotation, %v: %v", key, raw)
	}
	return true, nil
}
