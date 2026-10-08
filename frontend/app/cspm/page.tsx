import ComingSoonPage from "@/components/ComingSoonPage";

export default function CspmPage() {
  return (
    <ComingSoonPage
      title="CSPM"
      description="CSPM (Cloud Security Posture Management) continuously monitors your live cloud accounts (AWS, Azure, GCP) against security best practices — publicly exposed storage, overly broad IAM roles, unencrypted resources, drift from your intended IaC config. Where IaC security catches misconfiguration before deployment, CSPM catches it (and anything that changed since) after the fact, on infrastructure that's actually running."
    />
  );
}
