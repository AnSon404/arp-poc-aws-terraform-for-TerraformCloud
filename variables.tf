variable "name" {
  description = "Name of the VPC and EKS Cluster"
  type        = string
  default     = "arp-airflow-poc" # changed
}

variable "region" {
  description = "region"
  type        = string
  default     = "ap-southeast-1" # changed
}

variable "eks_cluster_version" {
  description = "EKS Cluster version"
  type        = string
  default     = "1.24" # changed from 1.23
}

variable "vpc_cidr" {
  description = "VPC CIDR"
  type        = string
  default     = "172.16.0.0/16" # changed
}
