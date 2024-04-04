package iamservice

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/iam"
	go_cfn "github.com/awslabs/goformation/v4/cloudformation"
	cfn_iam "github.com/awslabs/goformation/v4/cloudformation/iam"
	"github.com/pkg/errors"
	"k8s.io/klog/v2"
	iamv1 "sigs.k8s.io/cluster-api-provider-aws/v2/iam/api/v1beta1"
)

type Service interface {
	CreateServices(t go_cfn.Template, tags map[string]string) error
}

type serviceImpl struct {
	IAM *iam.IAM
}

func New(iamSvc *iam.IAM) Service {
	return &serviceImpl{
		IAM: iamSvc,
	}
}

func createClient() *iam.IAM {
	s, err := session.NewSession()
	if err != nil {
		errors.Wrap(err, "internal server error")
	}
	return iam.New(s)
}

func prioritySet(t go_cfn.Template, client *iam.IAM) (rmap map[string][]go_cfn.Resource, err error) {
	rmap = map[string][]go_cfn.Resource{}
	for _, resource := range t.Resources {
		if resource.AWSCloudFormationType() == configservice.ResourceTypeAwsIamRole {
			rmap["roles"] = append(rmap["roles"], resource)
		} else if resource.AWSCloudFormationType() == "AWS::IAM::InstanceProfile" {
			rmap["instanceProfiles"] = append(rmap["instanceProfiles"], resource)
		} else if resource.AWSCloudFormationType() == "AWS::IAM::ManagedPolicy" {
			rmap["policies"] = append(rmap["policies"], resource)
		} else {
			return nil, errors.Wrapf(err, "unknown resource type %v", resource)
		}
	}
	return rmap, nil
}

func (s *serviceImpl) CreateServices(t go_cfn.Template, tags map[string]string) error {
	client := createClient()
	rmap, err := prioritySet(t, client)
	if err != nil {
		return err
	}
	for _, resource := range rmap["roles"] {
		err := CreateRole(resource, tags, client)
		if err != nil {
			return err
		}
	}
	for _, resource := range rmap["instanceProfiles"] {
		err := CreateInstanceProfile(resource, tags, client)
		if err != nil {
			return err
		}
	}
	for _, resource := range rmap["policies"] {
		err := CreatePolicy(resource, tags, client)
		if err != nil {
			return err
		}
	}
	return nil
}

func CreateRole(resource go_cfn.Resource, tags map[string]string, client *iam.IAM) error {
	res := resource.(*cfn_iam.Role)
	tgs := []*iam.Tag{}
	for k, v := range tags {
		tag := iam.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		}
		tgs = append(tgs, &tag)
	}
	rawdata := res.AssumeRolePolicyDocument.(*iamv1.PolicyDocument)
	data, err := json.Marshal(rawdata)
	if err != nil {
		return errors.Wrapf(err, "corrupt policy document format for IAM role \"%s\"", res.RoleName)
	}
	_, err = client.CreateRole(&iam.CreateRoleInput{
		AssumeRolePolicyDocument: aws.String(string(data)),
		Description:              &res.Description,
		RoleName:                 &res.RoleName,
		Tags:                     tgs,
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeEntityAlreadyExistsException:
				klog.Warningf("IAM role \"%s\" already exists", res.RoleName)
			default:
				return errors.Wrapf(err, "failed to create IAM role \"%s\"", res.RoleName)
			}
		}
	}
	err = attachPoliciesToRole(&res.RoleName, res.ManagedPolicyArns, client)
	if err != nil {
		return err
	}
	klog.V(2).Infof("created \"%s\" CAPA managed IAM role", res.RoleName)
	return nil
}

func CreateInstanceProfile(resource go_cfn.Resource, tags map[string]string, client *iam.IAM) error {
	res := resource.(*cfn_iam.InstanceProfile)
	tgs := []*iam.Tag{}
	for k, v := range tags {
		tag := iam.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		}
		tgs = append(tgs, &tag)
	}
	_, err := client.CreateInstanceProfile(&iam.CreateInstanceProfileInput{
		InstanceProfileName: &res.InstanceProfileName,
		Tags:                tgs,
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeEntityAlreadyExistsException:
				klog.Warningf("instance profile \"%s\" already exists", res.InstanceProfileName)
			default:
				return errors.Wrapf(err, "failed to create instance profile \"%s\"", res.InstanceProfileName)
			}
		}
	}
	err = attachRoleToInstanceProf(resource, client)
	if err != nil {
		return err
	}
	klog.V(2).Infof("created \"%s\" CAPA managed instance profile", res.InstanceProfileName)
	return nil
}

func CreatePolicy(resource go_cfn.Resource, tags map[string]string, client *iam.IAM) error {
	res := resource.(*cfn_iam.ManagedPolicy)
	tgs := []*iam.Tag{}
	for k, v := range tags {
		tag := iam.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		}
		tgs = append(tgs, &tag)
	}
	rawdata := res.PolicyDocument.(*iamv1.PolicyDocument)
	data, err := json.Marshal(rawdata)
	if err != nil {
		return errors.Wrapf(err, "corrupt policy document format for policy \"%s\"", res.ManagedPolicyName)
	}
	create, err := client.CreatePolicy(&iam.CreatePolicyInput{
		Description:    &res.Description,
		PolicyDocument: aws.String(string(data)),
		PolicyName:     &res.ManagedPolicyName,
		Tags:           tgs,
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeEntityAlreadyExistsException:
				klog.Warningf("policy \"%s\" already exists", res.ManagedPolicyName)
				policies, err := listpolicies(client)
				if err != nil {
					return err
				}
				for _, policy := range policies {
					if *policy.PolicyName == res.ManagedPolicyName {
						return attachRolesToPolicy(policy, res.Roles, client)
					}
				}
			default:
				return errors.Wrapf(err, "failed to create CAPA managed IAM policy \"%s\"", res.ManagedPolicyName)
			}
		}
	}
	err = attachRolesToPolicy(create.Policy, res.Roles, client)
	if err != nil {
		return err
	}
	klog.V(2).Infof("created \"%s\" CAPA managed IAM policy", res.ManagedPolicyName)
	return nil
}

func attachRoleToInstanceProf(resource go_cfn.Resource, client *iam.IAM) error {
	res := resource.(*cfn_iam.InstanceProfile)
	roleName, err := getRoleName(res.Roles[0])
	if err != nil {
		return err
	}
	_, err = client.AddRoleToInstanceProfile(&iam.AddRoleToInstanceProfileInput{
		InstanceProfileName: &res.InstanceProfileName,
		RoleName:            &roleName,
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeEntityAlreadyExistsException, iam.ErrCodeLimitExceededException:
				klog.Warningf("instance profile \"%s\" is already attached to its IAM role", res.InstanceProfileName)
			default:
				return errors.Wrapf(err, "failed to attach instance profile \"%s\" to IAM role \"%s\"", res.InstanceProfileName, roleName)
			}
		}
	}
	return nil
}

func attachPoliciesToRole(rolename *string, awsManagedPolicies []string, client *iam.IAM) error {
	if awsManagedPolicies == nil {
		// klog.Warningf("no policies defined to attach to the IAM role \"%s\"", *rolename) // TODO
		return nil
	}
	for _, policy := range awsManagedPolicies {
		_, err := client.AttachRolePolicy(&iam.AttachRolePolicyInput{
			RoleName:  rolename,
			PolicyArn: &policy,
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case iam.ErrCodeEntityAlreadyExistsException:
					klog.Warningf("IAM role \"%s\" is already attached to policy", *rolename) // TODO should we output the policy arn? how safe is it
					continue
				default:
					return errors.Wrapf(err, "failed to attach IAM role \"%s\" to policy", *rolename) // TODO should we output the policy arn? how safe is it
				}
			}
		}
	}
	return nil
}

func attachRolesToPolicy(policy *iam.Policy, roles []string, client *iam.IAM) error {
	if roles == nil {
		// klog.Warningf("no IAM roles defined to attach to the policy \"%s\"", *policy.PolicyName) //TODO
		return nil
	}
	policyarn := policy.Arn
	for _, encodedRole := range roles {
		roleName, err := getRoleName(encodedRole)
		if err != nil {
			return err
		}
		_, err = client.AttachRolePolicy(&iam.AttachRolePolicyInput{
			PolicyArn: policyarn,
			RoleName:  &roleName,
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case iam.ErrCodeEntityAlreadyExistsException:
					klog.Warningf("policy \"%s\" is already attached to IAM role \"%s\"", *policy.PolicyName, roleName)
					continue
				default:
					return errors.Wrapf(err, "failed to attach policy \"%s\" to IAM role \"%s\"", *policy.PolicyName, roleName)
				}
			}
		}
	}
	return nil
}

func getRoleName(encodedRole string) (string, error) {
	var roleName string
	bytes, err := base64.StdEncoding.DecodeString(encodedRole)
	if err != nil {
		return "", err
	}
	roleRef := string(regexp.MustCompile(`(AWSIAMRole[a-zA-Z]+)`).Find(bytes))
	if roleRef == "AWSIAMRoleControllers" {
		roleName = fmt.Sprintf("controllers%s", iamv1.DefaultNameSuffix)
	} else if roleRef == "AWSIAMRoleNodes" {
		roleName = fmt.Sprintf("nodes%s", iamv1.DefaultNameSuffix)
	} else if roleRef == "AWSIAMRoleEKSControlPlane" {
		roleName = fmt.Sprintf("eks-controlplane%s", iamv1.DefaultNameSuffix)
	} else if roleRef == "AWSIAMRoleControlPlane" {
		roleName = fmt.Sprintf("control-plane%s", iamv1.DefaultNameSuffix)
	} else {
		return "", fmt.Errorf("unrecognised or no role found: \"%s\"", roleName)
	}
	return roleName, nil
}

func listpolicies(client *iam.IAM) ([]*iam.Policy, error) {
	list, err := client.ListPolicies(&iam.ListPoliciesInput{
		OnlyAttached: aws.Bool(false),
		Scope:        aws.String("Local"),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to list CAPA managed IAM policies")
	}
	if list.Policies == nil {
		klog.Warningf("no CAPA managed IAM policies detected on the AWS console")
		return nil, nil
	}
	return list.Policies, nil
}
