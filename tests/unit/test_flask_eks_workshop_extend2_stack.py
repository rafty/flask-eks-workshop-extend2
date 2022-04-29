import aws_cdk as core
import aws_cdk.assertions as assertions

from _stacks.flask_eks_workshop_extend2_stack import FlaskEksWorkshopExtend2Stack

# example tests. To run these tests, uncomment this file along with the example
# resource in flask_eks_workshop_extend2/flask_eks_workshop_extend2_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = FlaskEksWorkshopExtend2Stack(app, "flask-eks-workshop-extend2")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
