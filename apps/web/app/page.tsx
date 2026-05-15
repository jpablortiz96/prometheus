import { PrometheusDashboard } from "../components/prometheus-dashboard";
import { getApiBaseUrl } from "../lib/config";

export default function Home() {
  const apiBaseUrl = getApiBaseUrl();

  return <PrometheusDashboard apiBaseUrl={apiBaseUrl} />;
}
