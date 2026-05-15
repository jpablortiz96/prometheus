import { ThreatIntelLab } from "../../components/threat-intel-lab";
import { getApiBaseUrl } from "../../lib/config";

export default function ThreatIntelPage() {
  return <ThreatIntelLab apiBaseUrl={getApiBaseUrl()} />;
}
