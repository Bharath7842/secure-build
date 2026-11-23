import type { Metadata } from "next";

import PageContainer from "@/components/PageContainer";
import LlmMonitorDashboard from "@/components/monitor/LlmMonitorDashboard";

export const metadata: Metadata = {
  title: "LLM observability | Secure Build",
  description: "LLM calls, tokens and cost across every scan.",
};

export default function MonitorPage() {
  return (
    <PageContainer>
      <LlmMonitorDashboard />
    </PageContainer>
  );
}
