import json
import yaml
import aws_cdk
from aws_cdk import Stack
from constructs import Construct
from aws_cdk import aws_ec2
from aws_cdk import aws_route53
from aws_cdk import aws_certificatemanager
from aws_cdk import aws_eks
from aws_cdk import aws_iam
from aws_cdk import aws_dynamodb


class EksStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.configure = {
            'vpc_name': 'ekshandson',
            'vpc_cidr': '10.10.0.0/16',
            'cluster_name': 'ekshandson',

            # dynamodb
            'dynamodb_table_name': 'messages',
            'dynamodb_partition_name': 'uuid',

            # Domain & Cert
            'domain': 'yamazon.tk',
            'sub_domain': 'sample.yamazon.tk',
            'cert_arn': ('arn:aws:acm:ap-northeast-1:338456725408'
                         ':certificate/124163b3-7ec8-4cf7-af6e-f05d8bc6ce8f')
        }
        self.resources = {
            # 'vpc': None,
            # 'cluster': None,
            # 'table': None,
        }

        # VPC - three tier
        self.create_vpc()

        # EKS Cluster
        #   With
        #       AWS LoadBalancer Controller
        #       External DNS
        #       Fluentbit
        self.create_eks()

        # sub_domain の証明書の参照
        # ↓ 手動作成で要らなくなった
        # self.refer_certificate()
        # Deploy frontend app
        self.deploy_frontend()

        # # Deploy backend app
        self.create_dynamodb()
        self.deploy_backend()

    def create_vpc(self):
        # --------------------------------------------------------------
        # VPC
        #   Three Tire Network
        # --------------------------------------------------------------
        self.resources['vpc'] = aws_ec2.Vpc(
            self,
            'Vpc',
            vpc_name=self.configure.get('vpc_name'),
            cidr=self.configure.get('vpc_cidr'),
            max_azs=2,
            nat_gateways=1,
            subnet_configuration=[
                aws_ec2.SubnetConfiguration(
                    name="Front",
                    subnet_type=aws_ec2.SubnetType.PUBLIC,
                    cidr_mask=24),
                aws_ec2.SubnetConfiguration(
                    name="Application",
                    subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_NAT,
                    cidr_mask=24),
                aws_ec2.SubnetConfiguration(
                    name="DataStore",
                    subnet_type=aws_ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24),
            ]
        )
        return

    def create_eks(self):
        # --------------------------------------------------------------
        # EKS Cluster
        #   Owner role for EKS Cluster
        # --------------------------------------------------------------
        _owner_role = aws_iam.Role(
            scope=self,
            id='EksClusterOwnerRole',
            role_name='EksHandsOnEksClusterOwnerRole',
            assumed_by=aws_iam.AccountRootPrincipal()
        )
        self.resources['cluster'] = aws_eks.Cluster(
            self,
            'EksAppCluster',
            # cluster_name='ekshandson',
            cluster_name=self.configure.get('cluster_name'),
            version=aws_eks.KubernetesVersion.V1_21,
            default_capacity_type=aws_eks.DefaultCapacityType.NODEGROUP,
            # default NODEGROUP
            default_capacity=1,  # 3 OR 2
            default_capacity_instance=aws_ec2.InstanceType('t3.small'),
            # or t3.medium
            vpc=self.resources.get('vpc'),
            masters_role=_owner_role
        )
        # CI/CDでClusterを作成する際、IAM Userでkubectlを実行する際に追加する。
        # kubectl commandを実行できるIAM Userを追加
        # _cluster.aws_auth.add_user_mapping(
        #         user=aws_iam.User.from_user_name(
        #                 self, 'K8SUser-yagitatakashi', 'yagitatakashi'),
        #         groups=['system:masters']
        # )

        # ----------------------------------------------------------
        # ALBを使用する際、namespace='kube-system'に
        # AWS LoadBalancer Controllerをインストールする
        # (error) aws-load-balancer-controllerのPodが2つあるが、kube-systemはInstallしなくてもよいのか？？？？？
        # ↑　kubectl logsから確認した。
        # ----------------------------------------------------------
        self.install_aws_load_balancer_controller()

        # ----------------------------------------------------------
        # ExternalDNS コントローラをインストールする
        # ExternalDNSは TLS証明書持つALBのレコードをR53に登録する
        # ----------------------------------------------------------
        self.install_external_dns()

        # ----------------------------------------------------------
        # Cloudwatch Container Insights - Metrics / CloudWatch Agent
        # ----------------------------------------------------------
        self.deploy_cloudwatch_container_insights_metrics()

        # ----------------------------------------------------------
        # Cloudwatch Container Insights - Logs / fluentbit
        # ----------------------------------------------------------
        self.deploy_cloudwatch_container_insights_logs()
        return

    def install_aws_load_balancer_controller(self):
        # ----------------------------------------------------------
        # AWS LoadBalancer Controller for AWS ALB
        #   - Service Account
        #   - Namespace: kube-system
        #   - Deployment
        #   - Service
        # ----------------------------------------------------------
        _cluster = self.resources.get('cluster')
        awslbcontroller_sa = _cluster.add_service_account(
            'LBControllerServiceAccount',
            name='aws-load-balancer-controller',  # fixed name
            namespace='kube-system',
        )

        statements = []
        with open('./policies/awslbcontroller-policy.json') as f:
            data = json.load(f)
            for statement in data['Statement']:
                statements.append(aws_iam.PolicyStatement.from_json(statement))

        policy = aws_iam.Policy(
            self, 'AWSLoadBalancerControllerIAMPolicy', statements=statements)
        policy.attach_to_role(awslbcontroller_sa.role)

        aws_lb_controller_chart = _cluster.add_helm_chart(
            'AwsLoadBalancerController',
            chart='aws-load-balancer-controller',
            release='aws-load-balancer-controller',  # Deploymentの名前になる。
            repository='https://aws.github.io/eks-charts',
            namespace='kube-system',
            create_namespace=False,  # 追加
            values={
                'clusterName': _cluster.cluster_name,
                'region': self.region,
                'vpc': self.configure.get('vpc'),
                'serviceAccount': {  # dictに変更
                    'name': awslbcontroller_sa.service_account_name,
                    'create': False,
                    'annotations': {  # 追加
                        'eks.amazonaws.com/role-arn': awslbcontroller_sa.role.role_arn
                    }
                }
            }
        )
        aws_lb_controller_chart.node.add_dependency(awslbcontroller_sa)

    def install_external_dns(self):
        # External DNS Controller
        #
        # External DNS Controller sets A-Record in the Hosted Zone of Route 53.
        #
        # how to use:
        #   Set DomainName in annotations of Ingress Manifest.
        #   ex.
        #       external-dns.alpha.kubernetes.io/hostname: DOMAIN_NAME
        # see more info
        #   ('https://aws.amazon.com/jp/premiumsupport/'
        #    'knowledge-center/eks-set-up-externaldns/')

        _cluster = self.resources.get('cluster')
        external_dns_service_account = _cluster.add_service_account(
            'external-dns',
            name='external-dns',
            namespace='kube-system'
        )
        external_dns_policy_statement_json_1 = {
            'Effect': 'Allow',
            'Action': [
                'route53:ChangeResourceRecordSets'
            ],
            'Resource': [
                'arn:aws:route53:::hostedzone/*'
            ]
        }

        external_dns_policy_statement_json_2 = {
            'Effect': 'Allow',
            'Action': [
                'route53:ListHostedZones',
                'route53:ListResourceRecordSets'
            ],
            'Resource': ["*"]
        }

        external_dns_service_account.add_to_principal_policy(
            aws_iam.PolicyStatement.from_json(
                external_dns_policy_statement_json_1)
        )
        external_dns_service_account.add_to_principal_policy(
            aws_iam.PolicyStatement.from_json(
                external_dns_policy_statement_json_2)
        )

        external_dns_chart = _cluster.add_helm_chart(
            'external-dns"',
            chart='external-dns',
            version='1.7.1',  # change to '1.9.0'
            release='externaldns',
            repository='https://kubernetes-sigs.github.io/external-dns/',
            namespace='kube-system',
            values={
                'serviceAccount': {
                    'name': external_dns_service_account.service_account_name,
                    'create': False,
                },
                # 'resources': {
                #     'requests': {
                #         'cpu': '0.25',
                #         'memory': '0.5Gi'
                #     }
                # }
            }

        )
        external_dns_chart.node.add_dependency(external_dns_service_account)

    def deploy_cloudwatch_container_insights_metrics(self):
        # CloudWatch Agent
        # namespace: amazon-cloudwatch -> kube-system
        # See more info 'https://docs.aws.amazon.com/AmazonCloudWatch/latest'
        #               'monitoring/Container-Insights-setup-metrics.html'

        _cluster: aws_eks.Cluster = self.resources.get('cluster')

        # Create the Service Account
        cloudwatch_container_insight_sa: aws_iam.Role = \
            _cluster.add_service_account(
                id='cloudwatch-agent',
                name='cloudwatch-agent',
                namespace='kube-system',
            )

        cloudwatch_container_insight_sa.role.add_managed_policy(
            aws_iam.ManagedPolicy.from_aws_managed_policy_name(
                'CloudWatchAgentServerPolicy')
        )

        # ----------------------------------------------------------
        # CloudWatch ConfigMap Setting
        # ----------------------------------------------------------
        cwagentconfig_json = {
            'agent': {
                'region': self.region
            },
            'logs': {
                'metrics_collected': {
                    'kubernetes': {
                        'cluster_name': _cluster.cluster_name,
                        'metrics_collection_interval': 60
                    }
                },
                'force_flush_interval': 5,
                'endpoint_override': f'logs.{self.region}.amazonaws.com'
            },
            'metrics': {
                'metrics_collected': {
                    'statsd': {
                        'service_address': ':8125'
                    }
                }
            }
        }
        cw_agent_configmap = {
            'apiVersion': 'v1',
            'kind': 'ConfigMap',
            'metadata': {
                'name': 'cwagentconfig',
                'namespace': 'kube-system'
            },
            'data': {
                'cwagentconfig.json': json.dumps(cwagentconfig_json)
            }
        }
        _cluster.add_manifest('CloudwatchContainerInsightConfigMap',
                              cw_agent_configmap)

        # ----------------------------------------------------------
        # Apply multiple yaml documents. - cloudwatch-agent.yaml
        # ----------------------------------------------------------
        with open('./manifests/cloudwatch-agent.yaml', 'r') as f:
            _yaml_docs = list(yaml.load_all(f, Loader=yaml.FullLoader))
        for i, _yaml_doc in enumerate(_yaml_docs, 1):
            _cluster.add_manifest(f'CWAgent{i}', _yaml_doc)

    def deploy_cloudwatch_container_insights_logs_old(self):
        # Not Used
        #   Change from 'fluent-bit' to 'aws-for-fluent-bit'
        #
        # fluentbit
        # namespace: amazon-cloudwatch -> kube-system
        # more info
        #   ('https://docs.aws.amazon.com/AmazonCloudWatch/latest/'
        #    'monitoring/Container-Insights-setup-logs-FluentBit.html')
        # helm more info
        #   https://github.com/fluent/helm-charts/tree/main/charts/fluent-bit

        _cluster: aws_eks.Cluster = self.resources.get('cluster')

        # ---------------------------------------------------------------
        # Create the Service Account
        # ---------------------------------------------------------------
        fluentbit_policy_statement = {
            'Effect': 'Allow',
            'Action': [
                'logs:PutLogEvents',
                'logs:DescribeLogStreams',
                'logs:DescribeLogGroups',
                'logs:CreateLogStream',
                'logs:CreateLogGroup',
                'logs:PutRetentionPolicy'
            ],
            'Resource': ["*"]
        }
        fluentbit_sa: aws_iam.Role = _cluster.add_service_account(
            id='fluentbit_cloudwatch',
            name='fluentbit_cloudwatch',
            namespace='kube-system',
        )
        fluentbit_sa.add_to_principal_policy(
            aws_iam.PolicyStatement.from_json(fluentbit_policy_statement)
        )

        # aws-for-fluent-bit DaemonSetのデプロイ
        cloudwatch_helm_chart = _cluster.add_helm_chart(
            'FluentBitHelmChart',
            namespace='kube-system',
            repository='https://fluent.github.io/helm-charts',
            chart='fluent-bit',
            release='fluent-bit-cw',
            version='0.20.0',
            values={
                'serviceAccount': {
                    'name': fluentbit_sa.service_account_name,
                    'create': False
                },

                'cloudWatch': {'region': self.region},
                'kinesis': {'enabled': False},
                'elasticsearch': {'enabled': False},
                'firehose': {'enabled': False},
            }
        )
        cloudwatch_helm_chart.node.add_dependency(fluentbit_sa)

    def deploy_cloudwatch_container_insights_logs(self):
        # --------------------------------------------------------------
        # Cloudwatch Logs - fluent bit
        #   Namespace
        #   Service Account
        #   Deployment
        #   Service
        # https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-setup-logs-FluentBit.html
        # 1. namespace: amazon-cloudwatchを作成
        # 2. Service Account作成
        # --------------------------------------------------------------

        _cluster = self.resources.get('cluster')
        # namespace: amazon-cloudwatch
        cloudwatch_namespace_name = 'amazon-cloudwatch'
        cloudwatch_namespace_manifest = {
            'apiVersion': 'v1',
            'kind': 'Namespace',
            'metadata': {
                'name': cloudwatch_namespace_name,
                'labels': {
                    'name': cloudwatch_namespace_name
                }
            }
        }
        cloudwatch_namespace = _cluster.add_manifest(
                  'CloudWatchNamespace', cloudwatch_namespace_manifest)

        # Service Account for fluent bit
        fluentbit_service_account = _cluster.add_service_account(
            'FluentbitServiceAccount',
            name='cloudwatch-sa',
            namespace=cloudwatch_namespace_name
        )
        fluentbit_service_account.node.add_dependency(cloudwatch_namespace)
        # FluentBitの場合は以下のPolicyを使う。kinesisなどを使う場合はPolicyは異なる
        fluentbit_service_account.role.add_managed_policy(
            aws_iam.ManagedPolicy.from_aws_managed_policy_name(
                'CloudWatchAgentServerPolicy')
        )
        # logsの保持期間(logRetentionDays)の変更ポリシーを追加
        logs_retention_policy = {
            'Effect': 'Allow',
            'Action': [
                'logs:PutRetentionPolicy'
            ],
            'Resource': ["*"]
        }
        fluentbit_service_account.role.add_to_principal_policy(
            aws_iam.PolicyStatement.from_json(logs_retention_policy)
        )

        # aws-for-fluent-bit DaemonSetのデプロイ
        cloudwatch_helm_chart = _cluster.add_helm_chart(
            'FluentBitHelmChart',
            namespace=cloudwatch_namespace_name,
            repository='https://aws.github.io/eks-charts',
            chart='aws-for-fluent-bit',
            release='aws-for-fluent-bit',
            version='0.1.16',
            values={
                'serviceAccount': {
                    'name': fluentbit_service_account.service_account_name,
                    'create': False
                },
                'cloudWatch': {
                    'enabled': True,
                    'match': "*",
                    'region': self.region,
                    # 'logGroupName': f'/aws/eks/fluentbit-cloudwatch/logs/{_cluster.cluster_name}/application',
                    # 'logStreamPrefix': 'fluent-bit-',
                    'logRetentionDays': 7,
                    'autoCreateGroup': True,
                },
                'kinesis': {'enabled': False},
                'elasticsearch': {'enabled': False},
                'firehose': {'enabled': False},
            }
        )
        cloudwatch_helm_chart.node.add_dependency(fluentbit_service_account)

    def refer_certificate(self):
        # Sub Domainの証明書を作成する
        #   domain取得、HostedZoneが設定されてる前提
        #
        #     - freemon domain取得
        #     - R53 Hosted Zone登録は手動で行う
        #
        hosted_zone = aws_route53.HostedZone.from_lookup(
            self,
            'HostedZone',
            domain_name=self.configure.get('domain')
        )

        self.resources['cert'] = \
            aws_certificatemanager.Certificate.from_certificate_arn(
                self,
                id='SubDomainCert',
                certificate_arn=self.configure.get('cert_arn')
            )
        # 手動で作成することにした。
        # _cert = aws_certificatemanager.Certificate(
        #     self,
        #     'Certificate',
        #     domain_name=self.configure.get('sub_domain'),
        #     validation=aws_certificatemanager.CertificateValidation.from_dns(
        #         hosted_zone),
        # )
        # self.configure['certificate-arn'] = _cert.certificate_arn

    def deploy_frontend(self):
        # ----------------------------------------------------------
        # frontend
        #   - Namespace
        #   - Deployment
        #   - Service
        # ----------------------------------------------------------
        # ----------------------------------------------------------
        # frontend namespace
        # ----------------------------------------------------------
        frontend_name = 'frontend'
        frontend_namespace_name = frontend_name
        frontend_deployment_name = frontend_name
        frontend_service_name = frontend_name
        frontend_app_name = frontend_name
        frontend_app_label = {'app': f'{frontend_app_name}'}
        frontend_repo = ('338456725408.dkr.ecr.ap-northeast-1'
                         '.amazonaws.com/frontend')
        backend_url = 'http://backend.backend:5000/messages'  # ClusterIPで接続
        # ---------------------------------------------------------------------
        # 同一NamespaceのPodからは、metadata.nameのService名でこのServiceにアクセス
        # 別のNamespaceのPodからは、<Service名>.<Namespace名>でこのServiceにアクセス
        # ---------------------------------------------------------------------
        frontend_namespace_manifest = {
            'apiVersion': 'v1',
            'kind': 'Namespace',
            'metadata': {
                'name': frontend_namespace_name,
            },
        }

        _cluster = self.resources.get('cluster')
        frontend_namespace = _cluster.add_manifest('FrontendNamespace',
                                                   frontend_namespace_manifest)
        # --------------------------------------------------------------
        # frontend Deployment
        # ----------------------------------------------------------
        frontend_deployment_manifest = {
            'apiVersion': 'apps/v1',
            'kind': 'Deployment',
            'metadata': {
                'name': frontend_deployment_name,
                'namespace': frontend_namespace_name
            },
            'spec': {
                'selector': {'matchLabels': frontend_app_label},
                'replicas': 1,  # 2 or 3 and more
                'template': {
                    'metadata': {'labels': frontend_app_label},
                    'spec': {
                        'containers': [
                            {
                                'name': frontend_app_name,
                                'image': f'{frontend_repo}:latest',
                                'imagePullPolicy': 'Always',
                                'ports': [
                                    {
                                        'containerPort': 5000
                                    }
                                ],
                                'env': [
                                    {
                                        'name': 'BACKEND_URL',
                                        'value': backend_url
                                    }
                                ]
                            }
                        ]
                    }
                }
            }
        }
        frontend_deployment = _cluster.add_manifest(
            'FrontendDeployment', frontend_deployment_manifest)
        frontend_deployment.node.add_dependency(frontend_namespace)
        # --------------------------------------------------------------
        # frontend Service
        # ----------------------------------------------------------
        frontend_service_manifest = {
            'apiVersion': 'v1',
            'kind': 'Service',
            'metadata': {
                'name': frontend_service_name,
                'namespace': frontend_namespace_name
            },
            'spec': {
                # 'type': 'LoadBalancer',  # change to NodePort for ALB Ingress
                'type': 'NodePort',  # for ALB Ingress
                'selector': frontend_app_label,
                'ports': [
                    {
                        'protocol': 'TCP',
                        'port': 80,
                        'targetPort': 5000
                    }
                ]
            }
        }
        frontend_service = _cluster.add_manifest('FrontendService',
                                                 frontend_service_manifest)
        frontend_service.node.add_dependency(frontend_deployment)

        # --------------------------------------------------------------
        # Ingress - ALB, Cert,  R53 record
        # --------------------------------------------------------------
        _cert_arn = self.configure.get('cert_arn')
        _sub_domain = self.configure.get('sub_domain')
        frontend_aws_ingress_manifest = {
            'apiVersion': 'networking.k8s.io/v1',
            'kind': 'Ingress',
            'metadata': {
                'name': frontend_service_name,
                'namespace': frontend_namespace_name,
                'labels': frontend_app_label,
                'annotations': {
                    'kubernetes.io/ingress.class': 'alb',  # 追加
                    'alb.ingress.kubernetes.io/scheme': 'internet-facing',
                    'alb.ingress.kubernetes.io/target-type': 'ip',
                    # 'alb.ingress.kubernetes.io/listen-ports': '[{"HTTP": 80}, {"HTTPS": 443}]' # default
                    'alb.ingress.kubernetes.io/certificate-arn': _cert_arn,
                    'external-dns.alpha.kubernetes.io/hostname': _sub_domain,
                    # aliasレコードでも動くのか？
                    # 'external-dns.alpha.kubernetes.io/alias': 'true',
                    # ----------------------------------------------------
                },
            },
            'spec': {
                'rules': [
                    {
                        'http': {
                            'paths': [
                                {
                                    # 'path': '/*',  # "error":"ingress: frontend/frontend: prefix path
                                    # shouldn't contain wildcards: /*"
                                    'path': '/',
                                    'pathType': 'Prefix',
                                    'backend': {
                                        'service': {
                                            'name': frontend_service_name,
                                            'port': {
                                                'number': 80
                                            }
                                        }
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }
        frontend_ingress = _cluster.add_manifest('FrontendIngress',
                                                 frontend_aws_ingress_manifest)
        frontend_ingress.node.add_dependency(frontend_service)

    def create_dynamodb(self):
        # --------------------------------------------------------------
        #
        # DynamoDB
        #
        # --------------------------------------------------------------
        _table_name = self.configure.get('dynamodb_table_name')
        _partition_name = self.configure.get('dynamodb_partition_name')
        self.resources['table'] = aws_dynamodb.Table(
            self,
            id='DynamoDbTable',
            table_name=_table_name,
            partition_key=aws_dynamodb.Attribute(
                name=_partition_name,
                type=aws_dynamodb.AttributeType.STRING),
            read_capacity=1,
            write_capacity=1,
            removal_policy=aws_cdk.RemovalPolicy.DESTROY  # 削除
        )
        return

    def deploy_backend(self):
        # --------------------------------------------------------------
        # backend
        #   Namespace
        #   Service Account
        #   Deployment
        #   Service
        # ----------------------------------------------------------
        _cluster = self.resources.get('cluster')
        _table = self.resources.get('table')
        # ----------------------------------------------------------
        # backend namespace
        # ----------------------------------------------------------
        backend_name = 'backend'
        backend_namespace_name = backend_name
        backend_deployment_name = backend_name
        backend_service_name = backend_name
        backend_app_name = backend_name
        backend_app_label = {'app': f'{backend_app_name}'}
        backend_repo = '338456725408.dkr.ecr.ap-northeast-1.amazonaws.com/backend'

        backend_namespace_manifest = {
            'apiVersion': 'v1',
            'kind': 'Namespace',
            'metadata': {
                'name': backend_namespace_name,
            },
        }
        backend_namespace = _cluster.add_manifest('BackendNamespace',
                                                 backend_namespace_manifest)
        # --------------------------------------------------------------
        # backend
        #    IRSA IAM Role for Service Account
        # 　　DynamoDBへのアクセス許可
        # --------------------------------------------------------------
        backend_service_account = _cluster.add_service_account(
            'IamRoleForServiceAccount',  # この名前がIAM Role名に付加される
            # EksAppClusterIamRoleForServiceAccountRoleDefaultPolicyA7DA2A75
            name='backend-service-account',
            namespace=backend_namespace_name
        )
        backend_service_account.node.add_dependency(backend_namespace)

        # IRSAにAWS Secrets Managerへのアクセス権を与える
        dynamodb_messages_full_access_policy_statements = [
            {
                "Effect": "Allow",
                "Action": [
                    "dynamodb:List*",
                    "dynamodb:DescribeReservedCapacity*",
                    "dynamodb:DescribeLimits",
                    "dynamodb:DescribeTimeToLive"
                ],
                "Resource": ["*"]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "dynamodb:BatchGet*",
                    "dynamodb:DescribeStream",
                    "dynamodb:DescribeTable",
                    "dynamodb:Get*",
                    "dynamodb:Query",
                    "dynamodb:Scan",
                    "dynamodb:BatchWrite*",
                    "dynamodb:CreateTable",
                    "dynamodb:Delete*",
                    "dynamodb:Update*",
                    "dynamodb:PutItem"
                ],
                # "Resource": ["arn:aws:dynamodb:*:*:table/messages"]
                "Resource": [_table.table_arn]
            }
        ]

        for statement in dynamodb_messages_full_access_policy_statements:
            backend_service_account.add_to_principal_policy(
                aws_iam.PolicyStatement.from_json(statement)
            )

        # ----------------------------------------------------------
        # backend Deployment
        # ----------------------------------------------------------
        backend_deployment_manifest = {
            'apiVersion': 'apps/v1',
            'kind': 'Deployment',
            'metadata': {
                'name': backend_deployment_name,
                'namespace': backend_namespace_name
            },
            'spec': {
                'selector': {'matchLabels': backend_app_label},
                'replicas': 1,  # 2 or 3 and more
                'template': {
                    'metadata': {'labels': backend_app_label},
                    'spec': {
                        'serviceAccountName': backend_service_account.service_account_name,
                        'containers': [
                            {
                                'name': backend_app_name,
                                'image': f'{backend_repo}:latest',
                                'imagePullPolicy': 'Always',
                                'ports': [
                                    {
                                        'containerPort': 5000
                                    }
                                ],
                                'env': [
                                    {
                                        'name': 'AWS_DEFAULT_REGION',
                                        'value': self.region
                                    },
                                    {
                                        'name': 'DYNAMODB_TABLE_NAME',
                                        'value': _table.table_name  # 'message'
                                    }
                                ]
                            }
                        ]
                    }
                }
            }
        }
        backend_deployment = _cluster.add_manifest('BackendDeployment',
                                                   backend_deployment_manifest)
        backend_deployment.node.add_dependency(backend_service_account)

        # --------------------------------------------------------------
        # backend Service
        # ----------------------------------------------------------
        backend_service_manifest = {
            'apiVersion': 'v1',
            'kind': 'Service',
            'metadata': {
                'name': backend_service_name,
                'namespace': backend_namespace_name
            },
            'spec': {
                'type': 'ClusterIP',
                'selector': backend_app_label,
                'ports': [
                    {
                        'protocol': 'TCP',
                        'port': 5000,
                        'targetPort': 5000
                    }
                ]
            }
        }
        backend_service = _cluster.add_manifest('BackendService',
                                               backend_service_manifest)
        backend_service.node.add_dependency(backend_deployment)
