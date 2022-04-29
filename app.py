#!/usr/bin/env python3
import os
import aws_cdk as cdk
from _stacks.eks import EksStack


env = cdk.Environment(
    account=os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"]),
    region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"]),
)


app = cdk.App()
EksStack(app, "FlaskEksWorkshopExtend2Stack", env=env)

app.synth()
