import { DemoRoute } from "../../components/demo-route";
import { getApiBaseUrl } from "../../lib/config";

export default function DemoPage() {
  return <DemoRoute apiBaseUrl={getApiBaseUrl()} />;
}
