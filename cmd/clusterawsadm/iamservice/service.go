package iamservice

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/iam"
	go_cfn "github.com/awslabs/goformation/v4/cloudformation"
	cfn_iam "github.com/awslabs/goformation/v4/cloudformation/iam"
	iamv1 "sigs.k8s.io/cluster-api-provider-aws/v2/iam/api/v1beta1"
)

type Service interface {
	CreateService(t go_cfn.Template, tags map[string]string) error
	DeleteServices(t go_cfn.Template, tags map[string]string) error
	UpdateServices(t go_cfn.Template, tags map[string]string) error
}

type serviceImpl struct {
	IAM *iam.IAM
}

func New(iamSvc *iam.IAM) Service {
	return &serviceImpl{
		IAM: iamSvc,
	}
}

func CreateClient() *iam.IAM {
	s, err := session.NewSession()
	if err != nil {
		fmt.Print(err)
	}
	return iam.New(s)
}

func (s *serviceImpl) CreateService(t go_cfn.Template, tags map[string]string) error {
	client := CreateClient()
	resources := t.Resources
	err := priorityCreate(resources, tags, client)
	if err != nil {
		return err
	}
	return nil
}

func priorityCreate(resources go_cfn.Resources, tags map[string]string, client *iam.IAM) error {
	rmap := map[int][]go_cfn.Resource{}
	for _, resource := range resources {
		if resource.AWSCloudFormationType() == configservice.ResourceTypeAwsIamRole {
			rmap[1] = append(rmap[1], resource)
		} else if resource.AWSCloudFormationType() == "AWS::IAM::InstanceProfile" {
			rmap[2] = append(rmap[2], resource)
		} else if resource.AWSCloudFormationType() == "AWS::IAM::ManagedPolicy" {
			rmap[3] = append(rmap[3], resource)
		} else {
			return fmt.Errorf("error: unknown resource type: %v", resource)
		}
	}
	for _, resource := range rmap[1] {
		err := CreateRole(resource, tags, client)
		if err != nil {
			return err
		}
	}
	for _, resource := range rmap[2] {
		err := CreateInstanceProfile(resource, tags, client)
		if err != nil {
			return err
		}
	}
	for _, resource := range rmap[3] {
		err := CreatePolicy(resource, tags, client)
		if err != nil {
			return err
		}
	}
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
				attachRoleToInstanceProf(resource, client)
			case iam.ErrCodeInvalidInputException:
				return fmt.Errorf("error: %v, %v", iam.ErrCodeInvalidInputException, aerr.Error())
			case iam.ErrCodeLimitExceededException:
				return fmt.Errorf("error: %v, %v", iam.ErrCodeLimitExceededException, aerr.Error())
			case iam.ErrCodeConcurrentModificationException:
				return fmt.Errorf("error: %v, %v", iam.ErrCodeConcurrentModificationException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				return fmt.Errorf("error: %v, %v", iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				return fmt.Errorf(aerr.Error())
			}
		}
	}
	return attachRoleToInstanceProf(resource, client)
}

func attachRoleToInstanceProf(resource go_cfn.Resource, client *iam.IAM) error {
	res := resource.(*cfn_iam.InstanceProfile)
	_, err := client.AddRoleToInstanceProfile(&iam.AddRoleToInstanceProfileInput{
		InstanceProfileName: &res.InstanceProfileName,
		RoleName:            &res.InstanceProfileName,
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeEntityAlreadyExistsException:
				return fmt.Errorf("error: %v, %v", iam.ErrCodeEntityAlreadyExistsException, aerr.Error())
			case iam.ErrCodeNoSuchEntityException:
				return fmt.Errorf("error: %v, %v", iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeLimitExceededException:
				return fmt.Errorf("error: %v, %v", iam.ErrCodeLimitExceededException, aerr.Error())
			case iam.ErrCodeUnmodifiableEntityException:
				return fmt.Errorf("error: %v, %v", iam.ErrCodeUnmodifiableEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				return fmt.Errorf("error: %v, %v", iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				return fmt.Errorf(aerr.Error())
			}
		}
	}
	fmt.Printf("successfully attached IAM role to instance profile: %s", res.InstanceProfileName)
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
		return fmt.Errorf("error: marshalling %s resource: %w", res.RoleName, err)
	}
	create, err := client.CreateRole(&iam.CreateRoleInput{
		AssumeRolePolicyDocument: aws.String(string(data)),
		Description:              &res.Description,
		RoleName:                 &res.RoleName,
		Tags:                     tgs,
	})
	if err != nil {
		return fmt.Errorf("error: creating role %s: %w", res.RoleName, err)
	}
	return attachPoliciesToRole(create.Role.RoleName, res.ManagedPolicyArns, client)
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
		return fmt.Errorf("error: marshalling %s resource: %w", res.ManagedPolicyName, err)
	}
	create, err := client.CreatePolicy(&iam.CreatePolicyInput{
		Description:    &res.Description,
		PolicyDocument: aws.String(string(data)),
		PolicyName:     &res.ManagedPolicyName,
		Tags:           tgs,
	})
	if err != nil {
		return fmt.Errorf("error: creating policy %s: %w", res.ManagedPolicyName, err)
	}
	return attachRolesToPolicy(create.Policy, res.Roles, client)
}

func attachPoliciesToRole(rolename *string, managedpolicies []string, client *iam.IAM) error {
	if managedpolicies == nil {
		fmt.Printf("no managed policies for: %s", *rolename)
		return nil
	}
	for _, policy := range managedpolicies {
		_, err := client.AttachRolePolicy(&iam.AttachRolePolicyInput{
			RoleName:  rolename,
			PolicyArn: &policy,
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case iam.ErrCodeNoSuchEntityException:
					return fmt.Errorf("error: %v, %v", iam.ErrCodeNoSuchEntityException, aerr.Error())
				case iam.ErrCodeLimitExceededException:
					return fmt.Errorf("error: %v, %v", iam.ErrCodeLimitExceededException, aerr.Error())
				case iam.ErrCodeInvalidInputException:
					return fmt.Errorf("error: %v, %v", iam.ErrCodeInvalidInputException, aerr.Error())
				case iam.ErrCodeUnmodifiableEntityException:
					return fmt.Errorf("error: %v, %v", iam.ErrCodeUnmodifiableEntityException, aerr.Error())
				case iam.ErrCodePolicyNotAttachableException:
					return fmt.Errorf("error: %v, %v", iam.ErrCodePolicyNotAttachableException, aerr.Error())
				case iam.ErrCodeServiceFailureException:
					return fmt.Errorf("error: %v, %v", iam.ErrCodeServiceFailureException, aerr.Error())
				default:
					return fmt.Errorf(aerr.Error())
				}
			}
		}
		fmt.Printf("successfully attached %s to %s", policy, *rolename)
	}
	return nil
}

func getRoleName(roleRef string) (string, error) {
	var roleName string
	if roleRef == "AWSIAMRoleControllers" {
		roleName = fmt.Sprintf("controllers%s", iamv1.DefaultNameSuffix)
	} else if roleRef == "AWSIAMRoleNodes" {
		roleName = fmt.Sprintf("nodes%s", iamv1.DefaultNameSuffix)
	} else if roleRef == "AWSIAMRoleEKSControlPlane" {
		roleName = fmt.Sprintf("eks-controlplane%s", iamv1.DefaultNameSuffix)
	} else if roleRef == "AWSIAMRoleControlPlane" {
		roleName = fmt.Sprintf("control-plane%s", iamv1.DefaultNameSuffix)
	} else {
		return "", fmt.Errorf("unrecognised or no role found: %s", roleName)
	}

	return roleName, nil
}

func attachRolesToPolicy(policy *iam.Policy, roles []string, client *iam.IAM) error {
	policyarn := policy.Arn
	for _, role := range roles {
		//error here
		bytes, err := base64.RawStdEncoding.DecodeString(role)
		if err != nil {
			return fmt.Errorf("error: decoding %s: %w", role, err)
		}
		roleRef := strings.Trim(strings.TrimLeft(string(bytes), "{Ref:\\ \""), "\\ \"")
		roleName, err := getRoleName(roleRef)
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
				case iam.ErrCodeNoSuchEntityException:
					return fmt.Errorf("error: %v, %v", iam.ErrCodeNoSuchEntityException, aerr.Error())
				case iam.ErrCodeLimitExceededException:
					return fmt.Errorf("error: %v, %v", iam.ErrCodeLimitExceededException, aerr.Error())
				case iam.ErrCodeInvalidInputException:
					return fmt.Errorf("error: %v, %v", iam.ErrCodeInvalidInputException, aerr.Error())
				case iam.ErrCodeUnmodifiableEntityException:
					return fmt.Errorf("error: %v, %v", iam.ErrCodeUnmodifiableEntityException, aerr.Error())
				case iam.ErrCodePolicyNotAttachableException:
					return fmt.Errorf("error: %v, %v", iam.ErrCodePolicyNotAttachableException, aerr.Error())
				case iam.ErrCodeServiceFailureException:
					return fmt.Errorf("error: %v, %v", iam.ErrCodeServiceFailureException, aerr.Error())
				default:
					return fmt.Errorf(aerr.Error())
				}
			}
		}
		fmt.Printf("successfully attached %s to %s", roleRef, *policy.PolicyName)
	}
	return nil
}

func (s *serviceImpl) DeleteServices(t go_cfn.Template, tags map[string]string) error {
	client := CreateClient()
	attachedManagedPolicies := []*iam.AttachedPolicy{}
	for _, resource := range t.Resources {
		if resource.AWSCloudFormationType() == configservice.ResourceTypeAwsIamRole {
			res := resource.(*cfn_iam.Role)
			_, err := client.RemoveRoleFromInstanceProfile(&iam.RemoveRoleFromInstanceProfileInput{
				InstanceProfileName: &res.RoleName,
				RoleName:            &res.RoleName,
			})
			if err != nil {
				return fmt.Errorf("error: removing detaching role from instance profile %s: %w", res.RoleName, err)
			}
			_, err = client.DeleteInstanceProfile(&iam.DeleteInstanceProfileInput{
				InstanceProfileName: &res.RoleName,
			})
			if err != nil {
				return fmt.Errorf("error: deleting instance profile %s: %w", res.RoleName, err)
			}
			fmt.Printf("Successfully deleted: %s instance profile", res.RoleName)
			listManagedPolicies, err := client.ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{
				RoleName: &res.RoleName,
			})
			if err != nil {
				return fmt.Errorf("error: unable to list managed policies for %s: %w", res.RoleName, err)
			}
			for _, policy := range listManagedPolicies.AttachedPolicies {
				attachedManagedPolicies = append(attachedManagedPolicies, policy)
				_, err := client.DetachRolePolicy(&iam.DetachRolePolicyInput{
					RoleName:  &res.RoleName,
					PolicyArn: policy.PolicyArn,
				})
				if err != nil {
					return fmt.Errorf("error: detaching %s from %s: %w", *policy.PolicyName, res.RoleName, err)
				}
			}
			_, err = client.DeleteRole(&iam.DeleteRoleInput{
				RoleName: &res.RoleName,
			})
			if err != nil {
				return fmt.Errorf("error: deleting role %s: %w", res.RoleName, err)
			}
			fmt.Printf("Successfully deleted: %s role", res.RoleName)
		}
	}
	// can there be policies which aren't attached to any IAM resource?
	// use ListEntitiesForPolicy()?
	for _, policy := range attachedManagedPolicies {
		_, err := client.DeletePolicy(&iam.DeletePolicyInput{
			PolicyArn: policy.PolicyArn,
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case iam.ErrCodeNoSuchEntityException:
					return fmt.Errorf("error: %v, %v", iam.ErrCodeNoSuchEntityException, aerr.Error())
				case iam.ErrCodeLimitExceededException:
					return fmt.Errorf("error: %v, %v", iam.ErrCodeLimitExceededException, aerr.Error())
				case iam.ErrCodeInvalidInputException:
					return fmt.Errorf("error: %v, %v", iam.ErrCodeInvalidInputException, aerr.Error())
				case iam.ErrCodeDeleteConflictException:
					return fmt.Errorf("error: %v, %v", iam.ErrCodeDeleteConflictException, aerr.Error())
				case iam.ErrCodeServiceFailureException:
					return fmt.Errorf("error: %v, %v", iam.ErrCodeServiceFailureException, aerr.Error())
				default:
					return fmt.Errorf(aerr.Error())
				}
			}
		}
		fmt.Printf("Successfully deleted: %s policy", *policy.PolicyName)
	}
	return nil
}

// only updates existing policies
func (s *serviceImpl) UpdateServices(t go_cfn.Template, tags map[string]string) error {
	client := CreateClient()
	policies, err := listpolicies(client)
	if err != nil {
		return err
	}
	roles, err := listroles(client)
	if err != nil {
		return err
	}
	resources := t.Resources
	for _, resource := range resources {
		switch resource.AWSCloudFormationType() {
		case "AWS::IAM::ManagedPolicy":
			res := resource.(*cfn_iam.ManagedPolicy)
			for _, policy := range policies {
				if *policy.PolicyName == res.ManagedPolicyName {
					err := UpdatePolicy(*res, policy, client)
					if err != nil {
						return err
					}
				} else {
					continue
				}
			}
		case configservice.ResourceTypeAwsIamRole:
			for _, role := range roles {
				res := resource.(*cfn_iam.Role)
				fmt.Print(res, role)
				if role.RoleName == &res.RoleName {
					err := UpdateRole(res, role, client)
					if err != nil {
						return err
					}
				}
			}

		}
	}
	//return err
	return nil
}

func listroles(client *iam.IAM) ([]*iam.Role, error) {
	//unable to list user created roles only
	list, err := client.ListRoles(&iam.ListRolesInput{})
	if err != nil {
		return nil, fmt.Errorf("error: listing roles: %w", err)
	}
	return list.Roles, nil
}

// list policies from aws console can also list all the policies that are not aws managed but user/capa created
func listpolicies(client *iam.IAM) ([]*iam.Policy, error) {
	input := iam.ListPoliciesInput{
		OnlyAttached: aws.Bool(false),
		Scope:        aws.String("local"),
	}
	list, err := client.ListPolicies(&input)
	if err != nil {
		return nil, fmt.Errorf("error: listing policies: %w", err)
	}
	return list.Policies, nil
}

// what is there to update for roles? description?
func UpdateRole(res *cfn_iam.Role, role *iam.Role, client *iam.IAM) error {
	_, err := client.UpdateRole(&iam.UpdateRoleInput{
		RoleName: &res.RoleName,
		// Description: ,
	})
	if err != nil {
		return err
	}
	return nil
}

func UpdatePolicy(res cfn_iam.ManagedPolicy, policy *iam.Policy, client *iam.IAM) error {
	userPolicy := res.PolicyDocument.(*iamv1.PolicyDocument)
	list, err := client.ListPolicyVersions(&iam.ListPolicyVersionsInput{
		PolicyArn: policy.Arn,
	})
	if err != nil {
		return fmt.Errorf("error: listing policy versions for %s: %w", *policy.PolicyName, err)
	}
	var latestPolicyVersion *iam.PolicyVersion
	for _, version := range list.Versions {
		if latestPolicyVersion == nil {
			latestPolicyVersion = version
		}
		if version.CreateDate.After(*latestPolicyVersion.CreateDate) {
			latestPolicyVersion = version
		}
	}
	policyVersionInfo, err := client.GetPolicyVersion(&iam.GetPolicyVersionInput{
		PolicyArn: policy.Arn,
		VersionId: latestPolicyVersion.VersionId,
	})
	if err != nil {
		return fmt.Errorf("error: getting policy version for %s: %w", *policy.PolicyName, err)
	}
	policyDoc := policyVersionInfo.PolicyVersion.Document
	decoded, err := url.QueryUnescape(*policyDoc)
	if err != nil {
		return fmt.Errorf("error: decoding policy document %s of version %d: %w", *policy.PolicyName, latestPolicyVersion.VersionId, err)
	}
	awsVersionPolicy := &iamv1.PolicyDocument{}
	if err := json.Unmarshal([]byte(decoded), awsVersionPolicy); err != nil {
		return fmt.Errorf("error: unmarshalling policy document %s of version %d: %w", *policy.PolicyName, latestPolicyVersion.VersionId, err)
	}
	if !isEqual(awsVersionPolicy.Statement, userPolicy.Statement, client) {
		policyString, err := json.Marshal(userPolicy.Statement)
		if err != nil {
			return err
		}
		_, err = client.CreatePolicyVersion(&iam.CreatePolicyVersionInput{
			PolicyArn:      policy.Arn,
			PolicyDocument: aws.String(string(policyString)),
		})
		if err != nil {
			return fmt.Errorf("error: creating new policy version for %s: %w", *policy.PolicyName, err)
		}
	} else {
		fmt.Printf("policy document provided for \"%s\" is already present on the console \nno need to update the policy", *policy.PolicyName)
	}
	return nil
}

func isEqual(statements, userStatments iamv1.Statements, client *iam.IAM) bool {
	if len(statements) != len(userStatments) {
		return false
	}
	for _, statement := range statements {
		for _, userStatement := range userStatments {
			if len(statement.Resource) == len(userStatement.Resource) && len(statement.Action) == len(userStatement.Action) && len(statement.Condition) == len(userStatement.Condition) {
				return isEqualHelper(statement, userStatement)
			}
		}
	}
	return false
}

func isEqualHelper(statement, userStatement iamv1.StatementEntry) bool {
	var present bool
	resourcesLength := len(statement.Resource)
	for i := 0; i < resourcesLength; i++ {
		present = false
		for j := 0; j < resourcesLength; j++ {
			if statement.Resource[i] == userStatement.Resource[j] {
				present = true
				break
			}
		}
		if !present {
			return present
		}
	}
	for i := 0; i < len(statement.Action); i++ {
		present = false
		for j := 0; j < len(userStatement.Action); j++ {
			if statement.Action[i] == userStatement.Action[j] {
				present = true
				break
			}
		}
		if !present {
			return present
		}
	}
	return present
}
