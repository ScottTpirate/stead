import {
  createPlatformClient,
  QueryStore,
  PLATFORM_OPENAPI_VERSION,
  type AuthorizationContext,
} from "../../../packages/api-client/src/index";

import { observePlatformRequest } from "./performance";

export const platformContractVersion = PLATFORM_OPENAPI_VERSION;
export const platformClient = createPlatformClient({
  observeNetwork: observePlatformRequest,
});
export const platformQueryStore = new QueryStore();

export function replaceAuthorizationContext(context: AuthorizationContext): void {
  platformQueryStore.setAuthorizationContext(context);
}

export function clearAuthorizedPresentationState(): void {
  platformQueryStore.clearAuthorizationContext();
}
