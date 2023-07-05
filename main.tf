#---------------------------------------------------------------
# Providers
#---------------------------------------------------------------
provider "aws" {
  region = local.region
  access_key=var.aws_access_key_id
  secret_key=var.aws_secret_access_key
}

provider "kubernetes" {
  host                   = module.eks_blueprints.eks_cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_blueprints.eks_cluster_certificate_authority_data)
  token                  = data.aws_eks_cluster_auth.this.token
}

provider "helm" {
  kubernetes {
    host                   = module.eks_blueprints.eks_cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_blueprints.eks_cluster_certificate_authority_data)
    token                  = data.aws_eks_cluster_auth.this.token
  }
}

provider "kubectl" {
  apply_retry_count      = 10
  host                   = module.eks_blueprints.eks_cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_blueprints.eks_cluster_certificate_authority_data)
  token                  = data.aws_eks_cluster_auth.this.token
  load_config_file       = false
}

#---------------------------------------------------------------
# Data resources
#---------------------------------------------------------------
data "aws_eks_cluster_auth" "this" {
  name = module.eks_blueprints.eks_cluster_id
}
data "aws_availability_zones" "available" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

#---------------------------------------------------------------
# Local variables
#---------------------------------------------------------------
locals {
  name   = var.name
  region = var.region

  vpc_cidr                      = var.vpc_cidr
  azs                           = slice(data.aws_availability_zones.available.names, 0, 3)
  airflow_name                  = "airflow"
  airflow_service_account       = "airflow-webserver-sa"
  airflow_webserver_secret_name = "airflow-webserver-secret-key"
  efs_storage_class             = "efs-sc"
  efs_pvc                       = "airflowdags-pvc"

  tags = { 
    Environment  = "POC"
    "Created by" = "Nextlink"  
    Project      = "Airflow"
  }
}

#---------------------------------------------------------------
# EKS Blueprints
#---------------------------------------------------------------
module "eks_blueprints" {
  source = "./modules/eks_blueprints" # "../../.."

  cluster_name    = "${local.name}-eks"
  cluster_version = var.eks_cluster_version

  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnets

  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
    egress_all = {
      description      = "Node all egress"
      protocol         = "-1"
      from_port        = 0
      to_port          = 0
      type             = "egress"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
    }
    ingress_cluster_to_node_all_traffic = {
      description                   = "Cluster API to Nodegroup all traffic"
      protocol                      = "-1"
      from_port                     = 0
      to_port                       = 0
      type                          = "ingress"
      source_cluster_security_group = true
    }
  }

  map_roles = [
    {
      rolearn  = "arn:aws:iam::225238035913:role/arp-airflow-poc-datafeed-ec2-role"
      username = "kubectl-role"
      groups   = ["system:masters"]
    },
  ]
  map_users = [
    {
      userarn  = "arn:aws:iam::225238035913:user/arp_eks_admin"
      username = "arp_eks_admin"
      groups   = ["system:masters"]
    },
    {
      userarn  = "arn:aws:iam::225238035913:user/blo_arp_admin"
      username = "blo_arp_admin"
      groups   = ["system:masters"]
    },
    {
      userarn  = "arn:aws:iam::225238035913:user/kpoon_arp_admin"
      username = "kpoon_arp_admin"
      groups   = ["system:masters"]
    },
  ]

  managed_node_groups = {
    
    mng1 = {
      node_group_name = "core-node-grp"
      subnet_ids      = module.vpc.private_subnets

      instance_types = ["t3.medium"] 
      ami_type       = "AL2_x86_64"
      capacity_type  = "ON_DEMAND"

      disk_size = 100
      disk_type = "gp3"

      max_size               = 4 # ignore at /module/aws-eks-managed-node-groups/main.tf
      min_size               = 2 # ignore at /module/aws-eks-managed-node-groups/main.tf
      desired_size           = 4 # ignore at /module/aws-eks-managed-node-groups/main.tf
      create_launch_template = true
      launch_template_os     = "amazonlinux2eks"

      update_config = [{
        max_unavailable_percentage = 50
      }]

      k8s_labels = {
        Environment   = "preprod"
        Zone          = "test"
        WorkerType    = "ON_DEMAND"
        NodeGroupType = "core"
      }

      additional_tags = {
        Name                                                             = "core-node-grp"
        subnet_type                                                      = "private"
        "k8s.io/cluster-autoscaler/node-template/label/arch"             = "x86"
        "k8s.io/cluster-autoscaler/node-template/label/kubernetes.io/os" = "linux"
        "k8s.io/cluster-autoscaler/node-template/label/noderole"         = "core"
        "k8s.io/cluster-autoscaler/node-template/label/node-lifecycle"   = "on-demand"
        "k8s.io/cluster-autoscaler/${local.name}"                        = "owned"
        "k8s.io/cluster-autoscaler/enabled"                              = "true"
      }
    }
  }

  tags = local.tags
}

#---------------------------------------------------------------
# Kubernetes Add-ons
#---------------------------------------------------------------
module "eks_blueprints_kubernetes_addons" {
  source = "./modules/kubernetes-addons"

  eks_cluster_id       = module.eks_blueprints.eks_cluster_id
  eks_cluster_endpoint = module.eks_blueprints.eks_cluster_endpoint
  eks_oidc_provider    = module.eks_blueprints.oidc_provider
  eks_cluster_version  = module.eks_blueprints.eks_cluster_version

  enable_amazon_eks_vpc_cni            = true
  enable_amazon_eks_coredns            = true
  enable_amazon_eks_kube_proxy         = true
  enable_amazon_eks_aws_ebs_csi_driver = true
  amazon_eks_aws_ebs_csi_driver_config = { # most update is v1.18.0-eksbuild.1
    addon_version = "v1.17.0-eksbuild.1"
  }
  enable_cluster_autoscaler           = true
  enable_aws_efs_csi_driver           = true
  enable_aws_for_fluentbit            = true
  enable_aws_load_balancer_controller = true
  enable_secrets_store_csi_driver     = true 

  # Apache Airflow add-on with custom helm config
  enable_airflow = false # currently manually helm upgrade
  airflow_helm_config = {
    name             = local.airflow_name
    chart            = local.airflow_name
    repository       = "https://airflow.apache.org"
    version          = "1.8.0"
    namespace        = module.airflow_irsa.namespace
    create_namespace = false
    timeout          = 360
    wait             = false 
    description      = "Apache Airflow v2 Helm chart deployment configuration"
    values = [templatefile("${path.module}/values.yaml", {
      airflow_db_user = local.airflow_name
      airflow_db_name = module.db.db_instance_name
      airflow_db_host = element(split(":", module.db.db_instance_endpoint), 0)
      s3_bucket_name          = module.airflow_s3_bucket.s3_bucket_id
      webserver_secret_name   = local.airflow_webserver_secret_name
      airflow_service_account = local.airflow_service_account
      efs_pvc                 = local.efs_pvc
    })]

    set_sensitive = [
      {
        name  = "data.metadataConnection.pass"
        value = aws_secretsmanager_secret_version.postgres.secret_string
      }
    ]
  }
  tags = local.tags
}

#---------------------------------------------------------------
# RDS Postgres Database for Apache Airflow Metadata
#---------------------------------------------------------------
module "db" {
  source  = "./modules/terraform-aws-rds"
  # version = "~> 5.0"

  identifier = "${local.name}-${local.airflow_name}-postgres" 

  engine               = "postgres"
  engine_version       = "14.3"
  family               = "postgres14"
  major_engine_version = "14"
  instance_class       = "db.t3.medium" 
  availability_zone    = "ap-southeast-1a" 

  storage_type      = "io1"
  allocated_storage = 100
  iops              = 3000

  db_name                = local.airflow_name
  username               = local.airflow_name
  create_random_password = false
  password               = sensitive(aws_secretsmanager_secret_version.postgres.secret_string)
  port                   = 5432

  multi_az               = false
  db_subnet_group_name   = module.vpc.database_subnet_group
  vpc_security_group_ids = [module.security_group.security_group_id,"sg-00d843b60f75b25cc"]

  maintenance_window              = "Mon:00:00-Mon:03:00"
  backup_window                   = "03:00-06:00"
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  create_cloudwatch_log_group     = true

  backup_retention_period = 5
  skip_final_snapshot     = true
  deletion_protection     = true

  performance_insights_enabled          = true
  performance_insights_retention_period = 7
  create_monitoring_role                = true
  monitoring_interval                   = 60
  monitoring_role_name                  = "airflow-metastore"
  monitoring_role_use_name_prefix       = true
  monitoring_role_description           = "Airflow Postgres Metastore for monitoring role"

  parameters = [
    {
      name  = "autovacuum"
      value = 1
    },
    {
      name  = "client_encoding"
      value = "utf8"
    }
  ]

  tags = local.tags
}

module "airflow_s3_bucket" {
  source  = "./modules/terraform-aws-s3-bucket"
  # version = "~> 3.0"

  bucket = "${local.name}-airflow-logs-${data.aws_caller_identity.current.account_id}" 
  acl    = "private"

  force_destroy = true

  attach_deny_insecure_transport_policy = true
  attach_require_latest_tls_policy      = true

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = local.tags
}

#---------------------------------------------------------------
# Apache Airflow Postgres Metastore DB Master password
#---------------------------------------------------------------
resource "random_password" "postgres" {
  length  = 16
  special = false
}

resource "aws_secretsmanager_secret" "postgres" {
  name                    = "${local.name}-airflow-postgres" 
  recovery_window_in_days = 0 
}

resource "aws_secretsmanager_secret_version" "postgres" {
  secret_id     = aws_secretsmanager_secret.postgres.id
  secret_string = random_password.postgres.result
}

##---------------------------------------------------------------
## Apache Airflow Webserver Secret
##---------------------------------------------------------------
resource "random_id" "airflow_webserver" {
  byte_length = 16
}


resource "aws_secretsmanager_secret" "airflow_webserver" {
  name                    = "${local.name}-airflow_webserver_secret_key" 
  recovery_window_in_days = 0 
}

resource "aws_secretsmanager_secret_version" "airflow_webserver" {
  secret_id     = aws_secretsmanager_secret.airflow_webserver.id
  secret_string = random_id.airflow_webserver.hex
  lifecycle {
    ignore_changes = [
      secret_id,
      secret_string,
    ]
  }
}

#---------------------------------------------------------------
# Webserver Secret Key
#---------------------------------------------------------------
resource "kubectl_manifest" "airflow_webserver" {
  sensitive_fields = [
    "data.webserver-secret-key"
  ]
  
  yaml_body = <<-YAML
apiVersion: v1
kind: Secret
metadata:
   name: ${local.airflow_webserver_secret_name}
   namespace: ${module.airflow_irsa.namespace}
type: Opaque
data:
  webserver-secret-key: ${base64encode(aws_secretsmanager_secret_version.airflow_webserver.secret_string)}
YAML
}

#---------------------------------------------------------------
# GitSync User Secret Key # changed to use user login
#---------------------------------------------------------------
resource "kubectl_manifest" "gitsync_user" {
  
  yaml_body = <<-YAML
apiVersion: v1
kind: Secret
metadata:
   name: "git-credentials"
   namespace: ${module.airflow_irsa.namespace}
type: Opaque
data:
  GIT_SYNC_USERNAME: ${base64encode("deployadmin")}
  GIT_SYNC_PASSWORD: ${base64encode("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")}
YAML

}

#---------------------------------------------------------------
# Managing DAG files with GitSync - EFS Storage Class
#---------------------------------------------------------------
resource "kubectl_manifest" "efs_sc" {
  yaml_body = <<-YAML
    apiVersion: storage.k8s.io/v1
    kind: StorageClass
    metadata:
      name: ${local.efs_storage_class}
    provisioner: efs.csi.aws.com
    parameters:
      provisioningMode: efs-ap
      fileSystemId: ${module.efs.id}
      directoryPerms: "700"
      gidRangeStart: "1000"
      gidRangeEnd: "2000"
  YAML

  depends_on = [module.eks_blueprints.eks_cluster_id]
}

#---------------------------------------------------------------
# Persistent Volume Claim for EFS
#---------------------------------------------------------------
resource "kubectl_manifest" "efs_pvc" {
  yaml_body = <<-YAML
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: ${local.efs_pvc}
      namespace: ${module.airflow_irsa.namespace}
    spec:
      accessModes:
        - ReadWriteMany
      storageClassName: ${local.efs_storage_class}
      resources:
        requests:
          storage: 10Gi
  YAML

  depends_on = [kubectl_manifest.efs_sc]
}
#---------------------------------------------------------------
# EFS Filesystem for Airflow DAGs
#---------------------------------------------------------------

module "efs" {
  source  = "./modules/terraform-aws-efs"
  # version = "~> 1.0"

  creation_token = "${local.name}-efs" 
  name           = "${local.name}-efs" 

  mount_targets = { for k, v in toset(range(length(local.azs))) :
    element(local.azs, k) => { subnet_id = element(module.vpc.elasticache_subnets, k) } 
  }
  security_group_description = "${local.name} EFS security group"
  security_group_vpc_id      = module.vpc.vpc_id
  security_group_rules = {
    vpc = {
      description = "NFS ingress from VPC private subnets"
      cidr_blocks = module.vpc.private_subnets_cidr_blocks 
    }
  }
  attach_policy = false
  tags = local.tags
}

#---------------------------------------------------------------
# IRSA for Airflow S3 logging
#---------------------------------------------------------------
module "airflow_irsa" {
  source = "./modules/irsa"

  eks_cluster_id             = module.eks_blueprints.eks_cluster_id
  eks_oidc_provider_arn      = module.eks_blueprints.eks_oidc_provider_arn
  irsa_iam_policies          = [aws_iam_policy.airflow.arn]
  kubernetes_namespace       = "airflow"
  kubernetes_service_account = local.airflow_service_account
}

#---------------------------------------------------------------
# Creates IAM policy for accessing s3 bucket
#---------------------------------------------------------------
resource "aws_iam_policy" "airflow" {
  description = "IAM role policy for Airflow S3 Logs"
  name        = "${local.name}-airflow-irsa"
  policy      = data.aws_iam_policy_document.airflow_s3_logs.json
}

data "aws_iam_policy_document" "airflow_s3_logs" {
  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["arn:${data.aws_partition.current.partition}:s3:::${module.airflow_s3_bucket.s3_bucket_id}"]

    actions = [
      "s3:ListBucket"
    ]
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["arn:${data.aws_partition.current.partition}:s3:::${module.airflow_s3_bucket.s3_bucket_id}/*"]

    actions = [
      "s3:GetObject",
      "s3:PutObject",
    ]
  }
}

#---------------------------------------------------------------
# PostgreSQL RDS security group
#---------------------------------------------------------------
module "security_group" {
  source  = "./modules/terraform-aws-security-group"
  # version = "~> 4.0"

  name        = "${local.name}-airflow-postgres-sg" 
  description = "Complete PostgreSQL example security group"
  vpc_id      = module.vpc.vpc_id

  ingress_with_cidr_blocks = [
    {
      from_port   = 5432
      to_port     = 5432
      protocol    = "tcp"
      description = "PostgreSQL access from within VPC"
      cidr_blocks = module.vpc.vpc_cidr_block
    },
  ]

  tags = local.tags
}

#---------------------------------------------------------------
# VPC and Subnets
#---------------------------------------------------------------
module "vpc" {
  source  = "./modules/terraform-aws-vpc"
  # version = "~> 3.0"

  name = local.name
  cidr = local.vpc_cidr

  azs                       = local.azs
  map_public_ip_on_launch   = true
  public_subnets            = ["172.16.0.0/24", "172.16.1.0/24"] 
  elasticache_subnet_suffix = "file"
  elasticache_subnets       = ["172.16.3.0/24", "172.16.4.0/24", "172.16.5.0/24"]
  database_subnet_suffix    = "db"
  database_subnets          = ["172.16.6.0/24", "172.16.7.0/24", "172.16.8.0/24"]
  create_database_internet_gateway_route = true # changed for termporarily access db by internet
  private_subnet_suffix     = "eks"
  private_subnets           = ["172.16.32.0/19", "172.16.64.0/19", "172.16.96.0/19"]

  create_database_subnet_group       = true
  create_database_subnet_route_table = true

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  manage_default_network_acl    = true
  default_network_acl_tags      = { Name = "${local.name}-default" }
  manage_default_route_table    = true
  default_route_table_tags      = { Name = "${local.name}-default" }
  manage_default_security_group = true
  default_security_group_tags   = { Name = "${local.name}-default" }

  public_subnet_tags = {
    "kubernetes.io/cluster/${local.name}-eks" = "shared" 
    "kubernetes.io/role/elb"              = 1
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${local.name}-eks" = "shared" 
    "kubernetes.io/role/internal-elb"     = 1
  }

  tags = local.tags
}
