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
	priorityCreate(resources, tags, client)
	return nil
}

func priorityCreate(resources go_cfn.Resources, tags map[string]string, client *iam.IAM) {
	rmap := map[int][]go_cfn.Resource{}
	for _, resource := range resources {
		if resource.AWSCloudFormationType() == configservice.ResourceTypeAwsIamRole {
			rmap[1] = append(rmap[1], resource)
		}
		if resource.AWSCloudFormationType() == "AWS::IAM::InstanceProfile" {
			rmap[2] = append(rmap[2], resource)
		}
		if resource.AWSCloudFormationType() == "AWS::IAM::ManagedPolicy" {
			rmap[3] = append(rmap[3], resource)
		}
	}
	for _, resource := range rmap[1] {
		CreateRole(resource, tags, client)
	}
	for _, resource := range rmap[2] {
		CreateInstanceProfile(resource, tags, client)
	}
	for _, resource := range rmap[3] {
		CreatePolicy(resource, tags, client)
	}
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
	create, err := client.CreateInstanceProfile(&iam.CreateInstanceProfileInput{
		InstanceProfileName: &res.InstanceProfileName,
		Tags:                tgs,
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeEntityAlreadyExistsException:
				// fmt.Println(iam.ErrCodeEntityAlreadyExistsException, aerr.Error())
				addRoleToInstanceProf(resource, tags, client)
			case iam.ErrCodeInvalidInputException:
				fmt.Println(iam.ErrCodeInvalidInputException, aerr.Error())
			case iam.ErrCodeLimitExceededException:
				fmt.Println(iam.ErrCodeLimitExceededException, aerr.Error())
			case iam.ErrCodeConcurrentModificationException:
				fmt.Println(iam.ErrCodeConcurrentModificationException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		}
	}
	addRoleToInstanceProf(resource, tags, client)
	fmt.Println(create)
	return nil
}

func addRoleToInstanceProf(resource go_cfn.Resource, tags map[string]string, client *iam.IAM) {
	res := resource.(*cfn_iam.InstanceProfile)
	// diff between https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AssociateIamInstanceProfile.html and function I used?
	addRole, err := client.AddRoleToInstanceProfile(&iam.AddRoleToInstanceProfileInput{
		InstanceProfileName: &res.InstanceProfileName,
		RoleName:            &res.InstanceProfileName,
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeEntityAlreadyExistsException:
				fmt.Println(iam.ErrCodeEntityAlreadyExistsException, aerr.Error())
			case iam.ErrCodeNoSuchEntityException:
				fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeLimitExceededException:
				fmt.Println(iam.ErrCodeLimitExceededException, aerr.Error())
			case iam.ErrCodeUnmodifiableEntityException:
				fmt.Println(iam.ErrCodeUnmodifiableEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		}
	}
	fmt.Println(addRole)
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
		fmt.Println(err)
	}
	create, err := client.CreateRole(&iam.CreateRoleInput{
		AssumeRolePolicyDocument: aws.String(string(data)),
		Description:              &res.Description,
		RoleName:                 &res.RoleName,
		Tags:                     tgs,
	})
	if err != nil {
		fmt.Println(err)
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
		fmt.Println(err)
	}
	create, err := client.CreatePolicy(&iam.CreatePolicyInput{
		Description:    &res.Description,
		PolicyDocument: aws.String(string(data)),
		PolicyName:     &res.ManagedPolicyName,
		Tags:           tgs,
	})
	if err != nil {
		fmt.Println(err)
	}
	return attachRolesToPolicy(create.Policy.Arn, res.Roles, client)

}

func attachPoliciesToRole(rolename *string, managedpolicies []string, client *iam.IAM) error {
	if managedpolicies == nil {
		fmt.Printf("no managed policies for: %s", *rolename)
		return nil
	}
	for _, policy := range managedpolicies {
		attachRole, err := client.AttachRolePolicy(&iam.AttachRolePolicyInput{
			RoleName:  rolename,
			PolicyArn: &policy,
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case iam.ErrCodeNoSuchEntityException:
					fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
				case iam.ErrCodeLimitExceededException:
					fmt.Println(iam.ErrCodeLimitExceededException, aerr.Error())
				case iam.ErrCodeInvalidInputException:
					fmt.Println(iam.ErrCodeInvalidInputException, aerr.Error())
				case iam.ErrCodeUnmodifiableEntityException:
					fmt.Println(iam.ErrCodeUnmodifiableEntityException, aerr.Error())
				case iam.ErrCodePolicyNotAttachableException:
					fmt.Println(iam.ErrCodePolicyNotAttachableException, aerr.Error())
				case iam.ErrCodeServiceFailureException:
					fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
				default:
					fmt.Println(aerr.Error())
				}
			}
		}
		fmt.Println(attachRole)
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

func attachRolesToPolicy(policyarn *string, roles []string, client *iam.IAM) error {
	for _, role := range roles {
		bytes, err := base64.RawStdEncoding.DecodeString(role)
		if err != nil {
			fmt.Println(err)
		}
		roleRef := strings.Trim(strings.TrimLeft(string(bytes), "{Ref:\\ \""), "\\ \"")
		roleName, err := getRoleName(roleRef)
		if err != nil {
			fmt.Println(err)
		}
		attachPolicy, err := client.AttachRolePolicy(&iam.AttachRolePolicyInput{
			PolicyArn: policyarn,
			RoleName:  &roleName,
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case iam.ErrCodeNoSuchEntityException:
					fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
				case iam.ErrCodeLimitExceededException:
					fmt.Println(iam.ErrCodeLimitExceededException, aerr.Error())
				case iam.ErrCodeInvalidInputException:
					fmt.Println(iam.ErrCodeInvalidInputException, aerr.Error())
				case iam.ErrCodeUnmodifiableEntityException:
					fmt.Println(iam.ErrCodeUnmodifiableEntityException, aerr.Error())
				case iam.ErrCodePolicyNotAttachableException:
					fmt.Println(iam.ErrCodePolicyNotAttachableException, aerr.Error())
				case iam.ErrCodeServiceFailureException:
					fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
				default:
					fmt.Println(aerr.Error())
				}
			}
		}
		fmt.Println(attachPolicy)
	}
	return nil
}

func (s *serviceImpl) DeleteServices(t go_cfn.Template, tags map[string]string) error {
	client := CreateClient()
	attachedManagedPolicies := []*iam.AttachedPolicy{}
	for _, resource := range t.Resources {
		if resource.AWSCloudFormationType() == configservice.ResourceTypeAwsIamRole {
			res := resource.(*cfn_iam.Role)
			//this will not detach instance profiles from roles not associated with capa
			removerole, err := client.RemoveRoleFromInstanceProfile(&iam.RemoveRoleFromInstanceProfileInput{
				InstanceProfileName: &res.RoleName,
				RoleName:            &res.RoleName,
			})
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(removerole)
			delInstanceProfile, err := client.DeleteInstanceProfile(&iam.DeleteInstanceProfileInput{
				InstanceProfileName: &res.RoleName,
			})
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(delInstanceProfile)
			listManagedPolicies, err := client.ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{
				RoleName: &res.RoleName,
			})
			if err != nil {
				fmt.Println(err)
			}
			for _, policy := range listManagedPolicies.AttachedPolicies {
				attachedManagedPolicies = append(attachedManagedPolicies, policy)
				detachManagedPolicy, err := client.DetachRolePolicy(&iam.DetachRolePolicyInput{
					RoleName:  &res.RoleName,
					PolicyArn: policy.PolicyArn,
				})
				if err != nil {
					fmt.Println(err)
				}
				fmt.Println(detachManagedPolicy)
			}
			delRole, err := client.DeleteRole(&iam.DeleteRoleInput{
				RoleName: &res.RoleName,
			})
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(delRole)
		}
	}
	// can there be policies which aren't attached to any IAM resource?
	// use ListEntitiesForPolicy()?
	for _, policy := range attachedManagedPolicies {
		deletePolicy, err := client.DeletePolicy(&iam.DeletePolicyInput{
			PolicyArn: policy.PolicyArn,
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case iam.ErrCodeNoSuchEntityException:
					fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
				case iam.ErrCodeLimitExceededException:
					fmt.Println(iam.ErrCodeLimitExceededException, aerr.Error())
				case iam.ErrCodeInvalidInputException:
					fmt.Println(iam.ErrCodeInvalidInputException, aerr.Error())
				case iam.ErrCodeDeleteConflictException:
					fmt.Println(iam.ErrCodeDeleteConflictException, aerr.Error())
				case iam.ErrCodeServiceFailureException:
					fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
				default:
					fmt.Println(aerr.Error())
				}
			}
		}
		fmt.Println(deletePolicy)
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
					UpdatePolicy(*res, policy, client)
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
					UpdateRole(res, role, client)
					if err != nil {
						return err
					}
				}
			}

		}
	}
	return nil
}

func listroles(client *iam.IAM) ([]*iam.Role, error) {
	//unable to list user created roles only
	list, err := client.ListRoles(&iam.ListRolesInput{})
	if err != nil {
		return nil, err
	}
	return list.Roles, err
}

// list policies from aws console can also list all the policies that are not aws managed but user/capa created
func listpolicies(client *iam.IAM) ([]*iam.Policy, error) {
	input := iam.ListPoliciesInput{
		OnlyAttached: aws.Bool(false),
		Scope:        aws.String("local"),
	}
	list, err := client.ListPolicies(&input)
	if err != nil {
		return nil, err
	}
	return list.Policies, err
}

// what is there to update for roles? description?
func UpdateRole(res *cfn_iam.Role, role *iam.Role, client *iam.IAM) error {
	update, err := client.UpdateRole(&iam.UpdateRoleInput{
		RoleName: &res.RoleName,
		// Description: ,
	})
	if err != nil {
		return err
	}
	fmt.Println(update)
	return nil
}

func UpdatePolicy(res cfn_iam.ManagedPolicy, policy *iam.Policy, client *iam.IAM) error {
	userPolicy := res.PolicyDocument.(*iamv1.PolicyDocument)
	list, err := client.ListPolicyVersions(&iam.ListPolicyVersionsInput{
		PolicyArn: policy.Arn,
	})
	if err != nil {
		return err
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
		return fmt.Errorf("getting policy version %s (%s): %w", *policy.Arn, *latestPolicyVersion.VersionId, err)
	}
	policyDoc := policyVersionInfo.PolicyVersion.Document
	decoded, err := url.QueryUnescape(*policyDoc)
	if err != nil {
		return err
	}
	awsVersionPolicy := &iamv1.PolicyDocument{}
	if err := json.Unmarshal([]byte(decoded), awsVersionPolicy); err != nil {
		return err
	}
	if !isEqual(awsVersionPolicy.Statement, userPolicy.Statement, client) {
		policyString, err := json.Marshal(userPolicy.Statement)
		if err != nil {
			return err
		}
		create, err := client.CreatePolicyVersion(&iam.CreatePolicyVersionInput{
			PolicyArn:      policy.Arn,
			PolicyDocument: aws.String(string(policyString)),
		})
		if err != nil {
			return err
		}
		fmt.Println(create)
	} else {
		fmt.Println("NO UPDATE REQUIRED")
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
