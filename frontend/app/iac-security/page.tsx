import ComingSoonPage from "@/components/ComingSoonPage";

export default function IacSecurityPage() {
  return (
    <ComingSoonPage
      title="IaC Security"
      description="IaC (Infrastructure as Code) security scans your Terraform, CloudFormation, Kubernetes manifests, and Dockerfiles for misconfigurations — a public S3 bucket, an overly permissive security group, a container running as root — before that infrastructure is ever provisioned. Catching it here is strictly cheaper than catching it after deployment: it's a diff review instead of an incident."
    />
  );
}
