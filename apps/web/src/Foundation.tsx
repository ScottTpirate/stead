import { Workspace } from "./Workspace";
import { useRoute } from "./useRoute";

export function Foundation() {
  const { match, navigate } = useRoute();
  return <Workspace route={match} navigate={navigate} />;
}
