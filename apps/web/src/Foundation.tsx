import { AppShell } from "./AppShell";
import { useRoute } from "./useRoute";

export function Foundation() {
  const { match, navigate } = useRoute();
  return <AppShell route={match} navigate={navigate} />;
}
