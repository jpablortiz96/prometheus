import { ScenarioLab } from "../../components/scenario-lab";
import { getApiBaseUrl } from "../../lib/config";

export default function ScenariosPage() {
  return <ScenarioLab apiBaseUrl={getApiBaseUrl()} />;
}
