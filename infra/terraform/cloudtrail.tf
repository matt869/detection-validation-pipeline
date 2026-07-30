# Dedicated CloudTrail trail for validation.
#
# The T1562.008 test stops and restarts a trail. Doing that to the organisation
# trail would punch a real, unrecoverable hole in the audit record - so the
# emulation test targets this trail instead, and nothing else depends on it.
#
# The trail is deliberately separate rather than a filtered copy: a filter that
# was supposed to exclude production events is one misconfiguration away from
# not doing that.
#
#   terraform init && terraform plan
#
# Scope: the validation account only. Do not apply this into a production
# account, and do not point the emulation test at any other trail.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "region" {
  description = "Region hosting the validation trail."
  type        = string
  default     = "eu-west-1"
}

variable "validation_account_id" {
  description = "Account the validation trail belongs to. Guards against a misdirected apply."
  type        = string
}

variable "retention_days" {
  description = "How long validation logs are kept. Short: these are test artefacts."
  type        = number
  default     = 30
}

provider "aws" {
  region = var.region
  # Refuse to apply into an account other than the intended one.
  allowed_account_ids = [var.validation_account_id]

  default_tags {
    tags = {
      Project     = "detection-validation-pipeline"
      Environment = "validation"
      ManagedBy   = "terraform"
      # Read by humans deciding whether they may stop this trail.
      SafeToDisrupt = "true"
    }
  }
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "trail" {
  bucket        = "dvp-validation-trail-${var.validation_account_id}"
  force_destroy = true # test artefacts only
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    id     = "expire-validation-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = var.retention_days
    }
  }
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid     = "AWSCloudTrailAclCheck"
    actions = ["s3:GetBucketAcl"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = [aws_s3_bucket.trail.arn]
  }

  statement {
    sid     = "AWSCloudTrailWrite"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

resource "aws_cloudtrail" "validation" {
  name           = "dvp-validation-trail"
  s3_bucket_name = aws_s3_bucket.trail.id

  # Single-region and non-organisation on purpose: this trail must never be
  # load-bearing for anything, so that stopping it during a test is harmless.
  is_multi_region_trail         = false
  is_organization_trail         = false
  include_global_service_events = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.trail]
}

output "validation_trail_name" {
  description = "Pass this to the T1562.008 emulation test. Never the org trail."
  value       = aws_cloudtrail.validation.name
}

output "validation_trail_arn" {
  value = aws_cloudtrail.validation.arn
}
