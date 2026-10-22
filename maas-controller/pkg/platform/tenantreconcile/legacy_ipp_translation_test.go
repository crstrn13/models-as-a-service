package tenantreconcile

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var externalModelGVK = schema.GroupVersionKind{Group: "inference.opendatahub.io", Version: "v1alpha1", Kind: "ExternalModel"}
var externalProviderGVK = schema.GroupVersionKind{Group: "inference.opendatahub.io", Version: "v1alpha1", Kind: "ExternalProvider"}

func legacyTranslationModel(namespace, name, apiFormat, gatewayName, gatewayNamespace string, weight any) *unstructured.Unstructured {
	model := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "inference.opendatahub.io/v1alpha1",
		"kind":       "ExternalModel",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec": map[string]any{
			"gatewayRefs": []any{map[string]any{"name": gatewayName, "namespace": gatewayNamespace}},
			"externalProviderRefs": []any{map[string]any{
				"ref":         map[string]any{"name": name + "-provider"},
				"apiFormat":   apiFormat,
				"targetModel": "test",
				"path":        "/v1/messages",
				"weight":      weight,
			}},
		},
	}}
	model.SetGroupVersionKind(externalModelGVK)
	return model
}

func legacyTranslationProvider(namespace, name, providerType string) *unstructured.Unstructured {
	provider := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "inference.opendatahub.io/v1alpha1",
		"kind":       "ExternalProvider",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec":       map[string]any{"provider": providerType},
	}}
	provider.SetGroupVersionKind(externalProviderGVK)
	return provider
}

func inferenceListScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := pluginsMigrationScheme(t)
	scheme.AddKnownTypeWithName(externalModelGVK, &unstructured.Unstructured{})
	scheme.AddKnownTypeWithName(externalModelGVK.GroupVersion().WithKind("ExternalModelList"), &unstructured.UnstructuredList{})
	scheme.AddKnownTypeWithName(externalProviderGVK, &unstructured.Unstructured{})
	return scheme
}

func TestLegacyIPPTranslationModelsScopesActiveProviderBindings(t *testing.T) {
	params := PlatformParams{ModelNamespace: "tenant-a", GatewayName: "gateway-a", GatewayNamespace: "gateway-ns"}
	activeAnthropic := legacyTranslationModel("tenant-a", "anthropic-model", "messages", "gateway-a", "gateway-ns", nil)
	activeVertex := legacyTranslationModel("tenant-a", "vertex-model", "vertex-messages", "gateway-a", "gateway-ns", nil)
	activeOpenAI := legacyTranslationModel("tenant-a", "openai-model", "openai-chat", "gateway-a", "gateway-ns", nil)
	zeroWeightAnthropic := legacyTranslationModel("tenant-a", "disabled-model", "messages", "gateway-a", "gateway-ns", int64(0))
	otherGateway := legacyTranslationModel("tenant-a", "other-gateway-model", "messages", "gateway-b", "gateway-ns", nil)
	otherTenant := legacyTranslationModel("tenant-b", "other-tenant-model", "messages", "gateway-a", "gateway-ns", nil)
	cl := fake.NewClientBuilder().WithScheme(inferenceListScheme(t)).WithObjects(
		activeAnthropic,
		activeVertex,
		activeOpenAI,
		zeroWeightAnthropic,
		otherGateway,
		otherTenant,
		legacyTranslationProvider("tenant-a", "anthropic-model-provider", "anthropic"),
		legacyTranslationProvider("tenant-a", "vertex-model-provider", "vertex"),
		legacyTranslationProvider("tenant-a", "openai-model-provider", "openai"),
	).Build()

	got, err := legacyIPPTranslationModels(context.Background(), cl, params, &unstructured.Unstructured{})
	require.NoError(t, err)
	require.Equal(t, []string{
		"anthropic-model (apiFormat=messages, provider=anthropic)",
		"vertex-model (apiFormat=vertex-messages, provider=vertex)",
	}, got)
}

func TestLegacyIPPTranslationModelsDoNotAssumeOpenAIWireFormatMeansOpenAISafe(t *testing.T) {
	params := PlatformParams{ModelNamespace: "tenant-a", GatewayName: "gateway-a", GatewayNamespace: "gateway-ns"}
	for _, providerType := range []string{"azure", "vertex", "aws-bedrock"} {
		t.Run(providerType, func(t *testing.T) {
			model := legacyTranslationModel("tenant-a", providerType+"-model", "openai-chat", "gateway-a", "gateway-ns", nil)
			provider := legacyTranslationProvider("tenant-a", providerType+"-model-provider", providerType)
			cl := fake.NewClientBuilder().WithScheme(inferenceListScheme(t)).WithObjects(model, provider).Build()

			got, err := legacyIPPTranslationModels(context.Background(), cl, params, &unstructured.Unstructured{})
			require.NoError(t, err)
			require.Equal(t, []string{providerType + "-model (apiFormat=openai-chat, provider=" + providerType + ")"}, got)
		})
	}
}

func TestLegacyIPPTranslationModelsFailsClosedWhenProviderCannotBeResolved(t *testing.T) {
	model := legacyTranslationModel("tenant-a", "missing-provider", "openai-chat", "gateway-a", "gateway-ns", nil)
	cl := fake.NewClientBuilder().WithScheme(inferenceListScheme(t)).WithObjects(model).Build()

	got, err := legacyIPPTranslationModels(context.Background(), cl, PlatformParams{ModelNamespace: "tenant-a", GatewayName: "gateway-a", GatewayNamespace: "gateway-ns"}, &unstructured.Unstructured{})
	require.NoError(t, err)
	require.Equal(t, []string{"missing-provider (apiFormat=openai-chat, provider missing-provider-provider unresolved)"}, got)
}

func TestLegacyIPPTranslationModelsFailsClosedOnUnknownActiveFormat(t *testing.T) {
	model := legacyTranslationModel("tenant-a", "missing-format", "", "gateway-a", "gateway-ns", nil)
	cl := fake.NewClientBuilder().WithScheme(inferenceListScheme(t)).WithObjects(model).Build()
	_, err := legacyIPPTranslationModels(context.Background(), cl, PlatformParams{ModelNamespace: "tenant-a", GatewayName: "gateway-a", GatewayNamespace: "gateway-ns"}, &unstructured.Unstructured{})
	require.ErrorContains(t, err, "cannot prove it is safe to migrate")
}
