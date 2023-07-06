# aws-auth-configmap.tf
resource "kubernetes_config_map" "aws_auth" {
  count = var.create_eks ? 1 : 0

  metadata {
    name      = "aws-auth"
    namespace = "kube-system"
    labels = merge(
      {
        "app.kubernetes.io/managed-by" = "terraform-aws-eks-blueprints"
        "app.kubernetes.io/created-by" = "terraform-aws-eks-blueprints"
      },
      var.aws_auth_additional_labels
    )
  }

  data = {
    mapRoles = yamlencode(
      distinct(concat(
        local.managed_node_group_aws_auth_config_map,
        local.self_managed_node_group_aws_auth_config_map,
        local.windows_node_group_aws_auth_config_map,
        local.fargate_profiles_aws_auth_config_map,
        local.emr_on_eks_config_map,
        local.application_teams_config_map,
        local.platform_teams_config_map,
        var.map_roles,
      ))
    )
    mapUsers    = yamlencode(var.map_users)
    mapAccounts = yamlencode(var.map_accounts)
  }

  depends_on = [module.aws_eks.cluster_id, data.http.eks_cluster_readiness[0]]
}


# data.tf
data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_eks_cluster" "cluster" {
  count = var.create_eks ? 1 : 0
  name  = module.aws_eks.cluster_id
}

data "http" "eks_cluster_readiness" {
  count = var.create_eks ? 1 : 0

  url            = join("/", [data.aws_eks_cluster.cluster[0].endpoint, "healthz"])
  ca_certificate = base64decode(data.aws_eks_cluster.cluster[0].certificate_authority[0].data)
  timeout        = var.eks_readiness_timeout
}

data "aws_iam_session_context" "current" {
  arn = data.aws_caller_identity.current.arn
}

data "aws_iam_policy_document" "eks_key" {
  statement {
    sid    = "Allow access for all principals in the account that are authorized"
    effect = "Allow"
    actions = [
      "kms:CreateGrant",
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
    ]
    resources = ["*"]

    principals {
      type = "AWS"
      identifiers = [
        "arn:${local.context.aws_partition_id}:iam::${local.context.aws_caller_identity_account_id}:root"
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [local.context.aws_caller_identity_account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["eks.${local.context.aws_region_name}.amazonaws.com"]
    }
  }

  statement {
    sid    = "Allow direct access to key metadata to the account"
    effect = "Allow"
    actions = [
      "kms:Describe*",
      "kms:Get*",
      "kms:List*",
      "kms:RevokeGrant",
    ]
    resources = ["*"]

    principals {
      type = "AWS"
      identifiers = [
        "arn:${local.context.aws_partition_id}:iam::${local.context.aws_caller_identity_account_id}:root"
      ]
    }
  }

  statement {
    sid    = "Allow access for Key Administrators"
    effect = "Allow"
    actions = [
      "kms:*"
    ]
    resources = ["*"]

    principals {
      type = "AWS"
      identifiers = concat(
        var.cluster_kms_key_additional_admin_arns,
        [data.aws_iam_session_context.current.issuer_arn]
      )
    }
  }

  statement {
    sid    = "Allow use of the key"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
    ]
    resources = ["*"]

    principals {
      type = "AWS"
      identifiers = [
        local.cluster_iam_role_pathed_arn
      ]
    }
  }

  # Permission to allow AWS services that are integrated with AWS KMS to use the CMK,
  # particularly services that use grants.
  statement {
    sid    = "Allow attachment of persistent resources"
    effect = "Allow"
    actions = [
      "kms:CreateGrant",
      "kms:ListGrants",
      "kms:RevokeGrant",
    ]
    resources = ["*"]

    principals {
      type = "AWS"
      identifiers = [
        local.cluster_iam_role_pathed_arn
      ]
    }

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}


# eks-worker.tf
# ---------------------------------------------------------------------------------------------------------------------
# MANAGED NODE GROUPS
# ---------------------------------------------------------------------------------------------------------------------

module "aws_eks_managed_node_groups" {
  source = "../aws-eks-managed-node-groups"

  for_each = var.managed_node_groups

  managed_ng = each.value
  context    = local.node_group_context

  depends_on = [kubernetes_config_map.aws_auth]
}

# ---------------------------------------------------------------------------------------------------------------------
# SELF MANAGED NODE GROUPS
# ---------------------------------------------------------------------------------------------------------------------

module "aws_eks_self_managed_node_groups" {
  source = "../aws-eks-self-managed-node-groups"

  for_each = var.self_managed_node_groups

  self_managed_ng = each.value
  context         = local.node_group_context

  depends_on = [kubernetes_config_map.aws_auth]
}

# ---------------------------------------------------------------------------------------------------------------------
# FARGATE PROFILES
# ---------------------------------------------------------------------------------------------------------------------

module "aws_eks_fargate_profiles" {
  source = "../aws-eks-fargate-profiles"

  for_each = var.fargate_profiles

  fargate_profile = each.value
  context         = local.fargate_context

  depends_on = [kubernetes_config_map.aws_auth]
}


# locals.tf
locals {

  context = {
    # Data resources
    aws_region_name = data.aws_region.current.name
    # aws_caller_identity
    aws_caller_identity_account_id = data.aws_caller_identity.current.account_id
    aws_caller_identity_arn        = data.aws_caller_identity.current.arn
    # aws_partition
    aws_partition_id         = data.aws_partition.current.id
    aws_partition_dns_suffix = data.aws_partition.current.dns_suffix
  }

  eks_cluster_id     = module.aws_eks.cluster_id
  cluster_ca_base64  = module.aws_eks.cluster_certificate_authority_data
  cluster_endpoint   = module.aws_eks.cluster_endpoint
  vpc_id             = var.vpc_id
  private_subnet_ids = var.private_subnet_ids
  public_subnet_ids  = var.public_subnet_ids

  enable_workers            = length(var.self_managed_node_groups) > 0 || length(var.managed_node_groups) > 0 ? true : false
  worker_security_group_ids = local.enable_workers ? compact(flatten([[module.aws_eks.node_security_group_id], var.worker_additional_security_group_ids])) : []

  node_group_context = {
    # EKS Cluster Config
    eks_cluster_id    = local.eks_cluster_id
    cluster_ca_base64 = local.cluster_ca_base64
    cluster_endpoint  = local.cluster_endpoint
    cluster_version   = var.cluster_version
    # VPC Config
    vpc_id             = local.vpc_id
    private_subnet_ids = local.private_subnet_ids
    public_subnet_ids  = local.public_subnet_ids

    # Worker Security Group
    worker_security_group_ids = local.worker_security_group_ids

    # Data sources
    aws_partition_dns_suffix = local.context.aws_partition_dns_suffix
    aws_partition_id         = local.context.aws_partition_id

    iam_role_path                 = var.iam_role_path
    iam_role_permissions_boundary = var.iam_role_permissions_boundary

    # Service IPv4/IPv6 CIDR range
    service_ipv6_cidr = var.cluster_service_ipv6_cidr
    service_ipv4_cidr = var.cluster_service_ipv4_cidr

    tags = var.tags
  }

  fargate_context = {
    eks_cluster_id                = local.eks_cluster_id
    aws_partition_id              = local.context.aws_partition_id
    iam_role_path                 = var.iam_role_path
    iam_role_permissions_boundary = var.iam_role_permissions_boundary
    tags                          = var.tags
  }

  # Managed node IAM Roles for aws-auth
  managed_node_group_aws_auth_config_map = length(var.managed_node_groups) > 0 == true ? [
    for key, node in var.managed_node_groups : {
      rolearn : try(node.iam_role_arn, "arn:${local.context.aws_partition_id}:iam::${local.context.aws_caller_identity_account_id}:role/${module.aws_eks.cluster_id}-${node.node_group_name}")
      username : "system:node:{{EC2PrivateDNSName}}"
      groups : [
        "system:bootstrappers",
        "system:nodes"
      ]
    }
  ] : []

  # Self Managed node IAM Roles for aws-auth
  self_managed_node_group_aws_auth_config_map = length(var.self_managed_node_groups) > 0 ? [
    for key, node in var.self_managed_node_groups : {
      rolearn : try(node.iam_role_arn, "arn:${local.context.aws_partition_id}:iam::${local.context.aws_caller_identity_account_id}:role/${module.aws_eks.cluster_id}-${node.node_group_name}")
      username : "system:node:{{EC2PrivateDNSName}}"
      groups : [
        "system:bootstrappers",
        "system:nodes"
      ]
    } if node.launch_template_os != "windows"
  ] : []

  # Self Managed Windows node IAM Roles for aws-auth
  windows_node_group_aws_auth_config_map = length(var.self_managed_node_groups) > 0 && var.enable_windows_support ? [
    for key, node in var.self_managed_node_groups : {
      rolearn : "arn:${local.context.aws_partition_id}:iam::${local.context.aws_caller_identity_account_id}:role/${module.aws_eks.cluster_id}-${node.node_group_name}"
      username : "system:node:{{EC2PrivateDNSName}}"
      groups : [
        "system:bootstrappers",
        "system:nodes",
        "eks:kube-proxy-windows"
      ]
    } if node.launch_template_os == "windows"
  ] : []

  # Fargate node IAM Roles for aws-auth
  fargate_profiles_aws_auth_config_map = length(var.fargate_profiles) > 0 ? [
    for key, node in var.fargate_profiles : {
      rolearn : try(node.iam_role_arn, "arn:${local.context.aws_partition_id}:iam::${local.context.aws_caller_identity_account_id}:role/${module.aws_eks.cluster_id}-${node.fargate_profile_name}")
      username : "system:node:{{SessionName}}"
      groups : [
        "system:bootstrappers",
        "system:nodes",
        "system:node-proxier"
      ]
    }
  ] : []

  # EMR on EKS IAM Roles for aws-auth
  emr_on_eks_config_map = var.enable_emr_on_eks == true ? [
    {
      rolearn : "arn:${local.context.aws_partition_id}:iam::${local.context.aws_caller_identity_account_id}:role/AWSServiceRoleForAmazonEMRContainers"
      username : "emr-containers"
      groups : []
    }
  ] : []

  # Teams
  partition  = local.context.aws_partition_id
  account_id = local.context.aws_caller_identity_account_id

  # TODO - move this into `aws-eks-teams` to avoid getting out of sync
  platform_teams_config_map = length(var.platform_teams) > 0 ? [
    for platform_team_name, platform_team_data in var.platform_teams : {
      rolearn : "arn:${local.partition}:iam::${local.account_id}:role/${module.aws_eks.cluster_id}-${platform_team_name}-access"
      username : platform_team_name
      groups : [
        "system:masters"
      ]
    }
  ] : []

  # TODO - move this into `aws-eks-teams` to avoid getting out of sync
  application_teams_config_map = length(var.application_teams) > 0 ? [
    for team_name, team_data in var.application_teams : {
      rolearn : "arn:${local.partition}:iam::${local.account_id}:role/${module.aws_eks.cluster_id}-${team_name}-access"
      username : team_name
      groups : [
        "${team_name}-group"
      ]
    }
  ] : []

  cluster_iam_role_name        = var.iam_role_name == null ? "${var.cluster_name}-cluster-role" : var.iam_role_name
  cluster_iam_role_pathed_name = var.iam_role_path == null ? local.cluster_iam_role_name : "${trimprefix(var.iam_role_path, "/")}${local.cluster_iam_role_name}"
  cluster_iam_role_pathed_arn  = var.create_iam_role ? "arn:${local.context.aws_partition_id}:iam::${local.context.aws_caller_identity_account_id}:role/${local.cluster_iam_role_pathed_name}" : var.iam_role_arn
}


# main.tf
locals {
  cluster_encryption_config = length(var.cluster_encryption_config) > 0 ? var.cluster_encryption_config : [
    {
      provider_key_arn = try(module.kms[0].key_arn, var.cluster_kms_key_arn)
      resources        = ["secrets"]
    }
  ]
}

module "kms" {
  count  = var.create_eks && var.cluster_kms_key_arn == null && var.enable_cluster_encryption ? 1 : 0
  source = "../aws-kms"

  alias                   = "alias/${var.cluster_name}"
  description             = "${var.cluster_name} EKS cluster secret encryption key"
  policy                  = data.aws_iam_policy_document.eks_key.json
  deletion_window_in_days = var.cluster_kms_key_deletion_window_in_days
  tags                    = var.tags
}

module "aws_eks" {
  source  = "../terraform-aws-eks"
  # version = "v18.29.1"

  create = var.create_eks

  cluster_name     = var.cluster_name
  cluster_version  = var.cluster_version
  cluster_timeouts = var.cluster_timeouts

  create_iam_role               = var.create_iam_role
  iam_role_arn                  = var.iam_role_arn
  iam_role_use_name_prefix      = false
  iam_role_name                 = local.cluster_iam_role_name
  iam_role_path                 = var.iam_role_path
  iam_role_description          = var.iam_role_description
  iam_role_permissions_boundary = var.iam_role_permissions_boundary
  iam_role_additional_policies  = var.iam_role_additional_policies

  subnet_ids                           = var.private_subnet_ids
  control_plane_subnet_ids             = var.control_plane_subnet_ids
  cluster_endpoint_private_access      = var.cluster_endpoint_private_access
  cluster_endpoint_public_access       = var.cluster_endpoint_public_access
  cluster_endpoint_public_access_cidrs = var.cluster_endpoint_public_access_cidrs
  cluster_ip_family                    = var.cluster_ip_family
  cluster_service_ipv4_cidr            = var.cluster_service_ipv4_cidr

  vpc_id                                  = var.vpc_id
  create_cluster_security_group           = var.create_cluster_security_group
  cluster_security_group_id               = var.cluster_security_group_id
  cluster_security_group_name             = var.cluster_security_group_name
  cluster_security_group_use_name_prefix  = var.cluster_security_group_use_name_prefix
  cluster_security_group_description      = var.cluster_security_group_description
  cluster_additional_security_group_ids   = var.cluster_additional_security_group_ids
  cluster_security_group_additional_rules = var.cluster_security_group_additional_rules
  cluster_security_group_tags             = var.cluster_security_group_tags

  create_node_security_group           = var.create_node_security_group
  node_security_group_name             = var.node_security_group_name
  node_security_group_use_name_prefix  = var.node_security_group_use_name_prefix
  node_security_group_description      = var.node_security_group_description
  node_security_group_additional_rules = var.node_security_group_additional_rules
  node_security_group_tags             = var.node_security_group_tags

  enable_irsa              = var.enable_irsa
  openid_connect_audiences = var.openid_connect_audiences
  custom_oidc_thumbprints  = var.custom_oidc_thumbprints

  create_cloudwatch_log_group            = var.create_cloudwatch_log_group
  cluster_enabled_log_types              = var.cluster_enabled_log_types
  cloudwatch_log_group_retention_in_days = var.cloudwatch_log_group_retention_in_days
  cloudwatch_log_group_kms_key_id        = var.cloudwatch_log_group_kms_key_id

  attach_cluster_encryption_policy = false
  cluster_encryption_config        = var.enable_cluster_encryption ? local.cluster_encryption_config : []
  cluster_identity_providers       = var.cluster_identity_providers

  tags = var.tags
}

# ---------------------------------------------------------------------------------------------------------------------
# Amazon EMR on EKS Virtual Clusters
# ---------------------------------------------------------------------------------------------------------------------
module "emr_on_eks" {
  source = "../emr-on-eks"

  for_each = { for key, value in var.emr_on_eks_teams : key => value
    if var.enable_emr_on_eks && length(var.emr_on_eks_teams) > 0
  }

  emr_on_eks_teams              = each.value
  eks_cluster_id                = module.aws_eks.cluster_id
  iam_role_permissions_boundary = var.iam_role_permissions_boundary
  tags                          = var.tags

  depends_on = [kubernetes_config_map.aws_auth]
}

resource "kubernetes_config_map" "amazon_vpc_cni" {
  count = var.enable_windows_support ? 1 : 0
  metadata {
    name      = "amazon-vpc-cni"
    namespace = "kube-system"
  }

  data = {
    "enable-windows-ipam" = var.enable_windows_support ? "true" : "false"
  }

  depends_on = [
    module.aws_eks.cluster_id,
    data.http.eks_cluster_readiness[0]
  ]
}

# ---------------------------------------------------------------------------------------------------------------------
# Teams
# ---------------------------------------------------------------------------------------------------------------------
module "aws_eks_teams" {
  count  = length(var.application_teams) > 0 || length(var.platform_teams) > 0 ? 1 : 0
  source = "../aws-eks-teams"

  application_teams             = var.application_teams
  platform_teams                = var.platform_teams
  iam_role_permissions_boundary = var.iam_role_permissions_boundary
  eks_cluster_id                = module.aws_eks.cluster_id
  tags                          = var.tags
}


# outputs.tf
#-------------------------------
# EKS Cluster Module Outputs
#-------------------------------
output "eks_cluster_arn" {
  description = "Amazon EKS Cluster Name"
  value       = module.aws_eks.cluster_arn
}

output "eks_cluster_id" {
  description = "Amazon EKS Cluster Name"
  value       = module.aws_eks.cluster_id
}

output "eks_cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = module.aws_eks.cluster_certificate_authority_data
}

output "eks_cluster_endpoint" {
  description = "Endpoint for your Kubernetes API server"
  value       = module.aws_eks.cluster_endpoint
}

output "eks_oidc_issuer_url" {
  description = "The URL on the EKS cluster OIDC Issuer"
  value       = try(split("//", module.aws_eks.cluster_oidc_issuer_url)[1], "EKS Cluster not enabled") # TODO - remove `split()` since `oidc_provider` coverss https:// removal
}

output "oidc_provider" {
  description = "The OpenID Connect identity provider (issuer URL without leading `https://`)"
  value       = module.aws_eks.oidc_provider
}

output "eks_oidc_provider_arn" {
  description = "The ARN of the OIDC Provider if `enable_irsa = true`."
  value       = module.aws_eks.oidc_provider_arn
}

output "configure_kubectl" {
  description = "Configure kubectl: make sure you're logged in with the correct AWS profile and run the following command to update your kubeconfig"
  value       = "aws eks --region ${local.context.aws_region_name} update-kubeconfig --name ${module.aws_eks.cluster_id}"
}

output "eks_cluster_status" {
  description = "Amazon EKS Cluster Status"
  value       = module.aws_eks.cluster_status
}

output "eks_cluster_version" {
  description = "The Kubernetes version for the cluster"
  value       = module.aws_eks.cluster_version
}

#-------------------------------
# Cluster Security Group
#-------------------------------
output "cluster_primary_security_group_id" {
  description = "Cluster security group that was created by Amazon EKS for the cluster. Managed node groups use this security group for control-plane-to-data-plane communication. Referred to as 'Cluster security group' in the EKS console"
  value       = module.aws_eks.cluster_primary_security_group_id
}

output "cluster_security_group_id" {
  description = "EKS Control Plane Security Group ID"
  value       = module.aws_eks.cluster_security_group_id
}

output "cluster_security_group_arn" {
  description = "Amazon Resource Name (ARN) of the cluster security group"
  value       = module.aws_eks.cluster_security_group_arn
}

#-------------------------------
# EKS Worker Security Group
#-------------------------------
output "worker_node_security_group_arn" {
  description = "Amazon Resource Name (ARN) of the worker node shared security group"
  value       = try(module.aws_eks.node_security_group_arn, "EKS Node groups not enabled")
}

output "worker_node_security_group_id" {
  description = "ID of the worker node shared security group"
  value       = try(module.aws_eks.node_security_group_id, "EKS Node groups not enabled")
}

#-------------------------------
# Managed Node Groups Outputs
#-------------------------------
output "self_managed_node_groups" {
  description = "Outputs from EKS Self-managed node groups "
  value       = var.create_eks && length(var.self_managed_node_groups) > 0 ? module.aws_eks_self_managed_node_groups[*] : []
}

output "self_managed_node_group_iam_role_arns" {
  description = "IAM role arn's of self managed node groups"
  value       = var.create_eks && length(var.self_managed_node_groups) > 0 ? values({ for nodes in sort(keys(var.self_managed_node_groups)) : nodes => join(",", module.aws_eks_self_managed_node_groups[nodes].self_managed_nodegroup_iam_role_arns) }) : []
}

output "self_managed_node_group_autoscaling_groups" {
  description = "Autoscaling group names of self managed node groups"
  value       = var.create_eks && length(var.self_managed_node_groups) > 0 ? values({ for nodes in sort(keys(var.self_managed_node_groups)) : nodes => join(",", module.aws_eks_self_managed_node_groups[nodes].self_managed_asg_names) }) : []
}

output "self_managed_node_group_iam_instance_profile_id" {
  description = "IAM instance profile id of managed node groups"
  value       = var.create_eks && length(var.self_managed_node_groups) > 0 ? values({ for nodes in sort(keys(var.self_managed_node_groups)) : nodes => join(",", module.aws_eks_self_managed_node_groups[nodes].self_managed_nodegroup_iam_instance_profile_id) }) : []
}

output "self_managed_node_group_aws_auth_config_map" {
  description = "Self managed node groups AWS auth map"
  value       = local.self_managed_node_group_aws_auth_config_map[*]
}

output "windows_node_group_aws_auth_config_map" {
  description = "Windows node groups AWS auth map"
  value       = local.windows_node_group_aws_auth_config_map[*]
}

#-------------------------------
# Managed Node Groups Outputs
#-------------------------------
output "managed_node_groups" {
  description = "Outputs from EKS Managed node groups "
  value       = var.create_eks && length(var.managed_node_groups) > 0 ? module.aws_eks_managed_node_groups[*] : []
}

output "managed_node_groups_id" {
  description = "EKS Managed node groups id"
  value       = var.create_eks && length(var.managed_node_groups) > 0 ? values({ for nodes in keys(var.managed_node_groups) : nodes => join(",", module.aws_eks_managed_node_groups[nodes].managed_nodegroup_id) }) : []
}

output "managed_node_groups_status" {
  description = "EKS Managed node groups status"
  value       = var.create_eks && length(var.managed_node_groups) > 0 ? values({ for nodes in keys(var.managed_node_groups) : nodes => join(",", module.aws_eks_managed_node_groups[nodes].managed_nodegroup_status) }) : []
}

output "managed_node_group_arn" {
  description = "Managed node group arn"
  value       = var.create_eks && length(var.managed_node_groups) > 0 ? values({ for nodes in keys(var.managed_node_groups) : nodes => join(",", module.aws_eks_managed_node_groups[nodes].managed_nodegroup_arn) }) : []
}

output "managed_node_group_iam_role_names" {
  description = "IAM role names of managed node groups"
  value       = var.create_eks && length(var.managed_node_groups) > 0 ? values({ for nodes in keys(var.managed_node_groups) : nodes => join(",", module.aws_eks_managed_node_groups[nodes].managed_nodegroup_iam_role_name) }) : []
}

output "managed_node_group_iam_role_arns" {
  description = "IAM role arn's of managed node groups"
  value       = var.create_eks && length(var.managed_node_groups) > 0 ? values({ for nodes in keys(var.managed_node_groups) : nodes => join(",", module.aws_eks_managed_node_groups[nodes].managed_nodegroup_iam_role_arn) }) : []
}

output "managed_node_group_iam_instance_profile_id" {
  description = "IAM instance profile id of managed node groups"
  value       = var.create_eks && length(var.managed_node_groups) > 0 ? values({ for nodes in keys(var.managed_node_groups) : nodes => join(",", module.aws_eks_managed_node_groups[nodes].managed_nodegroup_iam_instance_profile_id) }) : []
}

output "managed_node_group_iam_instance_profile_arns" {
  description = "IAM instance profile arn's of managed node groups"
  value       = var.create_eks && length(var.managed_node_groups) > 0 ? values({ for nodes in keys(var.managed_node_groups) : nodes => join(",", module.aws_eks_managed_node_groups[nodes].managed_nodegroup_iam_instance_profile_arn) }) : []
}

output "managed_node_group_aws_auth_config_map" {
  description = "Managed node groups AWS auth map"
  value       = local.managed_node_group_aws_auth_config_map[*]
}

#-------------------------------
# Fargate Profile Outputs
#-------------------------------
output "fargate_profiles" {
  description = "Outputs from EKS Fargate profiles groups "
  value       = module.aws_eks_fargate_profiles
}

output "fargate_profiles_iam_role_arns" {
  description = "IAM role arn's for Fargate Profiles"
  value       = var.create_eks && length(var.fargate_profiles) > 0 ? { for nodes in sort(keys(var.fargate_profiles)) : nodes => module.aws_eks_fargate_profiles[nodes].eks_fargate_profile_role_name } : null
}

output "fargate_profiles_aws_auth_config_map" {
  description = "Fargate profiles AWS auth map"
  value       = local.fargate_profiles_aws_auth_config_map
}

#-------------------------------
# EMR on EKS Outputs
#-------------------------------
output "emr_on_eks_role_arn" {
  description = "IAM execution role ARN for EMR on EKS"
  value       = var.create_eks && var.enable_emr_on_eks ? values({ for nodes in sort(keys(var.emr_on_eks_teams)) : nodes => join(",", module.emr_on_eks[nodes].emr_on_eks_role_arn) }) : []
}

output "emr_on_eks_role_id" {
  description = "IAM execution role ID for EMR on EKS"
  value       = var.create_eks && var.enable_emr_on_eks ? values({ for nodes in sort(keys(var.emr_on_eks_teams)) : nodes => join(",", module.emr_on_eks[nodes].emr_on_eks_role_id) }) : []
}

#-------------------------------
# Teams(Soft Multi-tenancy) Outputs
#-------------------------------
output "teams" {
  description = "Outputs from EKS Fargate profiles groups "
  value       = var.create_eks && (length(var.platform_teams) > 0 || length(var.application_teams) > 0) ? module.aws_eks_teams[*] : []
}


# variables.tf
variable "tags" {
  description = "Additional tags (e.g. `map('BusinessUnit`,`XYZ`)"
  type        = map(string)
  default     = {}
}

#-------------------------------
# VPC Config for EKS Cluster
#-------------------------------
variable "vpc_id" {
  description = "VPC Id"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnets Ids for the cluster and worker nodes"
  type        = list(string)
  default     = []
}

variable "public_subnet_ids" {
  description = "List of public subnets Ids for the worker nodes"
  type        = list(string)
  default     = []
}

variable "control_plane_subnet_ids" {
  description = "A list of subnet IDs where the EKS cluster control plane (ENIs) will be provisioned. Used for expanding the pool of subnets used by nodes/node groups without replacing the EKS control plane"
  type        = list(string)
  default     = []
}

#-------------------------------
# EKS module variables (terraform-aws-modules/eks/aws)
#-------------------------------
variable "create_eks" {
  description = "Create EKS cluster"
  type        = bool
  default     = true
}

variable "cluster_timeouts" {
  description = "Create, update, and delete timeout configurations for the cluster"
  type        = map(string)
  default     = {}
}

variable "cluster_name" {
  description = "EKS Cluster Name"
  type        = string
  default     = ""
}

variable "cluster_version" {
  description = "Kubernetes `<major>.<minor>` version to use for the EKS cluster (i.e.: `1.23`)"
  type        = string
  default     = "1.23"
}

#-------------------------------
# EKS Cluster Security Groups
#-------------------------------
variable "create_cluster_security_group" {
  description = "Toggle to create or assign cluster security group"
  type        = bool
  default     = true
}

variable "cluster_security_group_name" {
  description = "Name to use on cluster security group created"
  type        = string
  default     = null
}

variable "cluster_security_group_use_name_prefix" {
  description = "Determines whether cluster security group name (`cluster_security_group_name`) is used as a prefix"
  type        = bool
  default     = true
}

variable "cluster_security_group_description" {
  description = "Description of the cluster security group created"
  type        = string
  default     = "EKS cluster security group"
}

variable "cluster_security_group_id" {
  description = "Security group to be used if creation of cluster security group is turned off"
  type        = string
  default     = ""
}

variable "cluster_additional_security_group_ids" {
  description = "List of additional, externally created security group IDs to attach to the cluster control plane"
  type        = list(string)
  default     = []
}

variable "cluster_security_group_additional_rules" {
  description = "List of additional security group rules to add to the cluster security group created. Set `source_node_security_group = true` inside rules to set the `node_security_group` as source"
  type        = any
  default     = {}
}

variable "cluster_security_group_tags" {
  description = "A map of additional tags to add to the cluster security group created"
  type        = map(string)
  default     = {}
}

#-------------------------------
# EKS Cluster VPC Config
#-------------------------------
variable "cluster_endpoint_public_access" {
  description = "Indicates whether or not the EKS public API server endpoint is enabled. Default to EKS resource and it is true"
  type        = bool
  default     = true
}

variable "cluster_endpoint_private_access" {
  description = "Indicates whether or not the EKS private API server endpoint is enabled. Default to EKS resource and it is false"
  type        = bool
  default     = false
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "List of CIDR blocks which can access the Amazon EKS public API server endpoint"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

#-------------------------------
# EKS Cluster ENCRYPTION
#-------------------------------
variable "cluster_kms_key_arn" {
  description = "A valid EKS Cluster KMS Key ARN to encrypt Kubernetes secrets"
  type        = string
  default     = null
}

variable "cluster_kms_key_deletion_window_in_days" {
  description = "The waiting period, specified in number of days (7 - 30). After the waiting period ends, AWS KMS deletes the KMS key"
  type        = number
  default     = 30
}

variable "cluster_kms_key_additional_admin_arns" {
  description = "A list of additional IAM ARNs that should have FULL access (kms:*) in the KMS key policy"
  type        = list(string)
  default     = []
}

variable "enable_cluster_encryption" {
  description = "Determines whether cluster encryption is enabled"
  type        = bool
  default     = true
}

variable "cluster_encryption_config" {
  description = "Configuration block with encryption configuration for the cluster"
  type = list(object({
    provider_key_arn = string
    resources        = list(string)
  }))
  default = []
}

#-------------------------------
# EKS Cluster Kubernetes Network Config
#-------------------------------
variable "cluster_ip_family" {
  description = "The IP family used to assign Kubernetes pod and service addresses. Valid values are `ipv4` (default) and `ipv6`. You can only specify an IP family when you create a cluster, changing this value will force a new cluster to be created"
  type        = string
  default     = "ipv4"
}

variable "cluster_service_ipv4_cidr" {
  description = "The CIDR block to assign Kubernetes service IP addresses from. If you don't specify a block, Kubernetes assigns addresses from either the 10.100.0.0/16 or 172.20.0.0/16 CIDR blocks"
  type        = string
  default     = null
}

variable "cluster_service_ipv6_cidr" {
  description = "The IPV6 Service CIDR block to assign Kubernetes service IP addresses"
  type        = string
  default     = null
}

#-------------------------------
# EKS Cluster CloudWatch Logging
#-------------------------------
variable "create_cloudwatch_log_group" {
  description = "Determines whether a log group is created by this module for the cluster logs. If not, AWS will automatically create one if logging is enabled"
  type        = bool
  default     = false
}

variable "cluster_enabled_log_types" {
  description = "A list of the desired control plane logging to enable"
  type        = list(string)
  default     = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
}

variable "cloudwatch_log_group_retention_in_days" {
  description = "Number of days to retain log events. Default retention - 90 days"
  type        = number
  default     = 90
}

variable "cloudwatch_log_group_kms_key_id" {
  description = "If a KMS Key ARN is set, this key will be used to encrypt the corresponding log group. Please be sure that the KMS Key has an appropriate key policy (https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html)"
  type        = string
  default     = null
}

#-------------------------------
# EKS Cluster IAM role
#-------------------------------

variable "create_iam_role" {
  description = "Determines whether a an IAM role is created or to use an existing IAM role"
  type        = bool
  default     = true
}

variable "iam_role_arn" {
  description = "Existing IAM role ARN for the cluster. Required if `create_iam_role` is set to `false`"
  type        = string
  default     = null
}

variable "iam_role_name" {
  description = "Name to use on IAM role created"
  type        = string
  default     = null
}

variable "iam_role_path" {
  description = "Cluster IAM role path"
  type        = string
  default     = null
}

variable "iam_role_description" {
  description = "Description of the role"
  type        = string
  default     = null
}

variable "iam_role_permissions_boundary" {
  description = "ARN of the policy that is used to set the permissions boundary for the IAM role"
  type        = string
  default     = null
}

variable "iam_role_additional_policies" {
  description = "Additional policies to be added to the IAM role"
  type        = list(string)
  default     = []
}

variable "enable_irsa" {
  description = "Determines whether to create an OpenID Connect Provider for EKS to enable IRSA"
  type        = bool
  default     = true
}

variable "openid_connect_audiences" {
  description = "List of OpenID Connect audience client IDs to add to the IRSA provider"
  type        = list(string)
  default     = []
}

variable "custom_oidc_thumbprints" {
  description = "Additional list of server certificate thumbprints for the OpenID Connect (OIDC) identity provider's server certificate(s)"
  type        = list(string)
  default     = []
}

variable "cluster_identity_providers" {
  description = "Map of cluster identity provider configurations to enable for the cluster. Note - this is different/separate from IRSA"
  type        = any
  default     = {}
}

#-------------------------------
# Node Groups
#-------------------------------
variable "managed_node_groups" {
  description = "Managed node groups configuration"
  type        = any
  default     = {}
}

variable "self_managed_node_groups" {
  description = "Self-managed node groups configuration"
  type        = any
  default     = {}
}

variable "enable_windows_support" {
  description = "Enable Windows support"
  type        = bool
  default     = false
}

#-------------------------------
# Worker Additional Variables
#-------------------------------
variable "create_node_security_group" {
  description = "Determines whether to create a security group for the node groups or use the existing `node_security_group_id`"
  type        = bool
  default     = true
}

variable "node_security_group_name" {
  description = "Name to use on node security group created"
  type        = string
  default     = null
}

variable "node_security_group_use_name_prefix" {
  description = "Determines whether node security group name (`node_security_group_name`) is used as a prefix"
  type        = bool
  default     = true
}

variable "node_security_group_description" {
  description = "Description of the node security group created"
  type        = string
  default     = "EKS node shared security group"
}

variable "node_security_group_additional_rules" {
  description = "List of additional security group rules to add to the node security group created. Set `source_cluster_security_group = true` inside rules to set the `cluster_security_group` as source"
  type        = any
  default     = {}
}

variable "node_security_group_tags" {
  description = "A map of additional tags to add to the node security group created"
  type        = map(string)
  default     = {}
}

variable "worker_additional_security_group_ids" {
  description = "A list of additional security group ids to attach to worker instances"
  type        = list(string)
  default     = []
}

#-------------------------------
# Fargate
#-------------------------------
variable "fargate_profiles" {
  description = "Fargate profile configuration"
  type        = any
  default     = {}
}

#-------------------------------
# aws-auth Config Map
#-------------------------------
variable "map_accounts" {
  description = "Additional AWS account numbers to add to the aws-auth ConfigMap"
  type        = list(string)
  default     = []
}

variable "map_roles" {
  description = "Additional IAM roles to add to the aws-auth ConfigMap"
  type = list(object({
    rolearn  = string
    username = string
    groups   = list(string)
  }))
  default = []
}

variable "map_users" {
  description = "Additional IAM users to add to the aws-auth ConfigMap"
  type = list(object({
    userarn  = string
    username = string
    groups   = list(string)
  }))
  default = []
}

variable "aws_auth_additional_labels" {
  description = "Additional kubernetes labels applied on aws-auth ConfigMap"
  type        = map(string)
  default     = {}
}

variable "eks_readiness_timeout" {
  description = "The maximum time (in seconds) to wait for EKS API server endpoint to become healthy"
  type        = number
  default     = "600"
}

#-------------------------------
# Amazon EMR on EKS
#-------------------------------
variable "enable_emr_on_eks" {
  description = "Enable EMR on EKS"
  type        = bool
  default     = false
}

variable "emr_on_eks_teams" {
  description = "EMR on EKS Teams config"
  type        = any
  default     = {}
}

#-------------------------------
# TEAMS (Soft Multi-tenancy)
#-------------------------------
variable "application_teams" {
  description = "Map of maps of Application Teams to create"
  type        = any
  default     = {}
}

variable "platform_teams" {
  description = "Map of maps of platform teams to create"
  type        = any
  default     = {}
}


# versions.tf
terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 3.72"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.10"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.4.1"
    }
    local = {
      source  = "hashicorp/local"
      version = ">= 2.1"
    }
    null = {
      source  = "hashicorp/null"
      version = ">= 3.1"
    }
    http = {
      source  = "terraform-aws-modules/http"
      version = "2.4.1"
    }
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = ">= 1.14"
    }
  }
}