#!/bin/bash
# ------------------------------------------------------------------------
# ./IAM_Automation.sh
# Michael Dennis M. Cresido, 06/30/2022
#
# This Shell script is created to serve as a notification for
# accounts(both for User and Service Account) that has their password or
# access key expired. This also includes inactive accounts
# Another notice is sent to the respective recipients if the users
# failed to comply with the security compliance.
# IAM User Account will be deleted for disabled accounts
#
# ------------------------------------------------------------------------
# Version 1.0 - Script is completed
# Version 1.1 - Added deletion of account
# Version 1.2 - Added deletion of account, validation of service account vs
#               user account, deletion of access keys and added different
#               kinds of notification ----- Jan 30
# Version 1.3 - Completed use cases that was provided in the flow chart ---- February 2, 2023
# Version 1.4 - Tested and completed UAT ---- February 7, 2023
# Version 1.5 - Changes has been added in the email content ---- February 26, 2023
#             - Tested and completed UAT ---- March 01, 2023
# Version 1.6 - Enabled Removal function ---- March 12, 2023
# Version 1.7 - Disabled Removal function and added ELIF statement in main fuction that
#               distinguish named and service account. ---- March 14, 2023

mainFunction(){
    mainProfile=$1 #"deltekdev-cli"
    mainLogPath=$2
    #Retrieve all users
    users=`aws iam list-users --output text --query 'Users[*].[UserName]' --profile $mainProfile`

    #mainAccount=$(caseProfileFunction "$mainProfile")
    dateToday=$(date '+%Y-%m-%d')
    mainLog="$mainProfile"_"$dateToday"

    mainMailEnvironment=$(caseEnvironmentFunction "$mainProfile")
    mainUserInfoFilePath="/Auto_Offboarding/IAM_Automation/report/AWS-IAM-PasswordInfo_$mainProfile.csv"
    mainResetPasswordFilePath="null"
    mainAccessKeyRotationFilepath="null"
    mainReenablingAccountFilepath="null"
    mainResetPassword_DelFunc="user-access-password"
    mainAccessKeyDeletion_DelFunc="access-key-deleted"
    mainInactivityUserDeletion_DelFunc="user-access-inactive"
    mainServiceAccountExpiry_DelFunc="sa-access-key-notif"

    mainInactiveExpiryDays=90
    mainPasswordExpiryDays=60
    mainUserAccessKeyExpiryDays=60
    mainServiceAccountAccessKeyExpiryDays=365



    for mainUser in $users;
        #Retrieve all tags from each IAM user
        do
            sleep 0.5
            #Initializing loop variable
            employeeID=""
            mail=""
            mainRecipient=""
            login_enabled=""
            mfa_enabled=""
            mainUAKey=""
            mainLastActivityDate=""
            mainLastPasswordChangeDate=""
            mainAccountCreationDate=""
            mainPasswordLastusedInDays=""
            mainLastActivity=""
            mainPasswordLastChangedInDays=""
            mainPasswordReset=""
            mainUAKey=""

            # Line calls the list of tags attached in the user.
            read -r employeeID mail <<< $(serviceAccountVerificationFunction "$mainUser" "$mainProfile")

            echo "This is currently called in the main function. This is the value of the email tag: $mail. User that is currently checking: $mainUser" >> $mainLogPath/$mainLog.txt

            if [ -z $mail ] && [ "$employeeID" != "service-account" ];
                then
                    mainRecipient="CloudInfraSRE@deltek.com";


            elif [ -z $mail ] && [ "$employeeID" == "service-account" ];
                then
                    mainRecipient="MatthewMumford@deltek.com,JuvenRobertoEdillor@deltek.com,ShaneAllen@deltek.com,CloudInfraSRE@deltek.com";

            else echo "This is the e-mail of the user: $mail" >> $mainLogPath/$mainLog.txt

                    mainRecipient=$mail

            fi;
                echo "This is the mainRepicient variable: $mainRecipient" >> $mainLogPath/$mainLog.txt



            # This is an if else statement that separates service account and normal user account
            if [ "$employeeID" != "service-account" ];

                then login_enabled=`aws iam get-login-profile --user-name $mainUser --profile $mainProfile 2>/dev/null`;
                     mfa_enabled=`aws iam list-mfa-devices --user-name $mainUser --profile $mainProfile --query 'MFADevices[].[SerialNumber]' --output text | wc -l`
                # This is a validation statement if console access is enabled in the user account
                # If the key variable is null/empty, it means there are no login profile or the user can't login using AWS console.
                if [ -z "$login_enabled" ] && [ "$mfa_enabled" -eq 0 ];
                    then echo "This  is currentyly treated as service account: $mainUser." >> $mainLogPath/$mainLog.txt;
                
                        mainSAKey=$(accessKeyVerificationFunction "$mainUser" "$mainProfile" "$mainServiceAccountAccessKeyExpiryDays" "AKSAR" "$mainMailEnvironment" "$mainAccessKeyRotationFilepath" "$mainServiceAccountExpiry_DelFunc" "$mainRecipient")
                        echo $mainSAKey >> $mainLogPath/$mainLog.txt
                elif [ -z "$login_enabled" ] && [ "$mfa_enabled" -eq 1 ];
                    then echo "This has no login profile: $mainUser. Proceed in checking Access Keys of this account" >> $mainLogPath/$mainLog.txt;

                        mainUAKey=$(accessKeyVerificationFunction "$mainUser" "$mainProfile" "$mainUserAccessKeyExpiryDays" "AKUAR" "$mainMailEnvironment" "$mainAccessKeyRotationFilepath" "$mainAccessKeyDeletion_DelFunc" "$mainRecipient")

                        echo $mainUAKey >> $mainLogPath/$mainLog.txt

                # All active accounts with console access will fall into this statement
                else echo "Verifying user account activity: $mainUser";

                    # Retrieve the Last Activity Date, Last Password Date and Creatiion of the user account.
                    # mainUserInfoFilePath is generated using get-credential-report

                    mainLastActivityDate=`gawk -F "," -v username="$mainUser" '{ if($1 == username) print $5}' $mainUserInfoFilePath`;
                    mainLastPasswordChangeDate=`gawk -F "," -v username="$mainUser" '{ if($1 == username) print $6}' $mainUserInfoFilePath`;

                    echo "This is the last date when IAM User account: $mainUser has been used $mainLastActivityDate" >> $mainLogPath/$mainLog.txt
                    echo "This is the last date when password was last change in this: $mainUser has been used $mainLastPasswordChangeDate" >> $mainLogPath/$mainLog.txt

                    # This is a validation that checks if the user has logged in using their console access.
                    # If the last activity date is null/empty, creation date will be used as the baseline of these inactive accounts.
                    if [ "$mainLastActivityDate" == "no_information" ] || [ "$mainLastActivityDate" == "N/A" ];
                        then
                            mainAccountCreationDate=`gawk -F "," -v username="$mainUser" '{ if($1 == username) print $3}' $mainUserInfoFilePath`;
                            mainPasswordLastusedInDays=$(expirydateFunction "$mainAccountCreationDate" "$mainInactiveExpiryDays");
                            echo "CREATED DATE: Days before inactivity compliance: $mainPasswordLastusedInDays. User account: $mainUser" >> $mainLogPath/$mainLog.txt

                            mainLastActivity=$(expiryVerificationFunction "$mainPasswordLastusedInDays" "$mainUser" "$mainInactiveExpiryDays" "$mainAccountCreationDate" "UIR" "$mainMailEnvironment" "$mainReenablingAccountFilepath" "$mainProfile" "$mainInactivityUserDeletion_DelFunc" "NA" "$mainRecipient");

                    # If it has last activity date, it will just proceed in validating if the account is expired or not.
                    else
                        mainPasswordLastusedInDays=$(expirydateFunction "$mainLastActivityDate" "$mainInactiveExpiryDays");
                        echo "LAST ACTIVITY DATE: Days before inactivity compliance: $mainPasswordLastusedInDays. User account: $mainUser" >> $mainLogPath/$mainLog.txt
                        mainLastActivity=$(expiryVerificationFunction "$mainPasswordLastusedInDays" "$mainUser" "$mainInactiveExpiryDays" "$mainLastActivityDate" "UIR" "$mainMailEnvironment" "$mainReenablingAccountFilepath" "$mainProfile" "$mainInactivityUserDeletion_DelFunc" "NA" "$mainRecipient");

                    fi;
                    mainPasswordLastChangedInDays=$(expirydateFunction $mainLastPasswordChangeDate $mainPasswordExpiryDays);

                    echo "Days before expiry: $mainPasswordLastChangedInDays. User account: $mainUser" >> $mainLogPath/$mainLog.txt

                    mainPasswordReset=$(expiryVerificationFunction "$mainPasswordLastChangedInDays" "$mainUser" "$mainPasswordExpiryDays" "$mainLastPasswordChangeDate" "UER" "$mainMailEnvironment" "$mainResetPasswordFilePath" "$mainProfile" "$mainResetPassword_DelFunc" "NA" "$mainRecipient");

                    echo $mainLastActivity >> $mainLogPath/$mainLog.txt
                    echo $mainPasswordReset >> $mainLogPath/$mainLog.txt
                    mainUAKey=$(accessKeyVerificationFunction "$mainUser" "$mainProfile" "$mainUserAccessKeyExpiryDays" "AKUAR" "$mainMailEnvironment" "$mainAccessKeyRotationFilepath" "$mainAccessKeyDeletion_DelFunc" "$mainRecipient")
                    echo $mainUAKey >> $mainLogPath/$mainLog.txt

               fi;
            # This is the statement where service account access key IDs is verified
            else echo "This is an access key Verification: $mainUser" >> $mainLogPath/$mainLog.txt;

                    #mainSAKey=$(accessKeyVerificationFunction "$mainUser" "$mainProfile" "$mainServiceAccountAccessKeyExpiryDays" "AKSAR" "$mainMailEnvironment" "$mainAccessKeyRotationFilepath" "$mainServiceAccountExpiry_DelFunc" "$mainRecipient")
                    #echo $mainSAKey >> $mainLogPath/$mainLog.txt
            fi;
        done;
    }
removalFunction(){
    remProfile=$1
    remUsername=$2

    #Removing console access
    if $(aws iam get-login-profile --user-name "$remUsername" --profile "$remProfile" &>/dev/null);
        then
            echo "Removing Login profile: $remUsername";
            aws iam delete-login-profile --user-name "$remUsername" --profile "$remProfile"
    else echo "No LOGIN Profile is attached to this user: $remUsername";
    fi;

    #Removing all attached group from the user
    if [ $(aws iam list-groups-for-user --user-name "$remUsername" --profile "$remProfile" --query 'Groups[].[GroupName]' --output text | wc -l) -gt 0 ]
        then
            echo "List all groups attached in the user: $remUsername";
            for remGroup in `aws iam list-groups-for-user --user-name "$remUsername" --profile "$remProfile" --query 'Groups[].[GroupName]' --output text`;
                do
                    echo "Removing group: $remGroup from user: $remUsername"
                    aws iam remove-user-from-group --user-name "$remUsername" --profile "$remProfile" --group-name "$remGroup"
                done;
        else echo "No groups to be deleted from this user: $remUsername";
    fi;

    #Removing Inline Policy
    if [ $(aws iam list-user-policies --user-name "$remUsername" --profile "$remProfile" --query 'PolicyNames[]' --output text | wc -l) -gt 0 ];
        then
            for remPolicy in `aws iam list-user-policies --user-name "$remUsername" --profile "$remProfile" --query 'PolicyNames[]' --output text`;
                do
                    echo "Removing inline policy '$remPolicy'"
                    aws iam delete-user-policy --user-name "$remUsername" --profile "$remProfile" --policy-name "$remPolicy"
                done
    else echo "No INLINE Policy is attached to this user: $remUsername";
    fi;

    #Removing attached IAM Policy
    if [ $(aws iam list-attached-user-policies --user-name "$remUsername" --profile "$remProfile" --query 'AttachedPolicies[]' --output text | wc -l) -gt 0 ];
        then
            for remPolicyArn in `aws iam list-attached-user-policies --user-name "$remUsername" --profile "$remProfile" --query 'AttachedPolicies[].[PolicyArn]' --output text`;
                do
                    echo "Removing inline policy '$remPolicyArn'"
                    aws iam detach-user-policy --user-name "$remUsername" --profile "$remProfile" --policy-arn "$remPolicyArn"
                done
    else echo "No INLINE Policy is attached to this user: $remUsername";
    fi;

    #Removing access keys
    if [ $(aws iam list-access-keys --user-name "$remUsername" --profile "$remProfile" --query 'AccessKeyMetadata[].[AccessKeyId]' --output text | wc -l) -gt 0 ];
        then
            echo "List all access keys attached in the user: $remUsername";
            for remAccesskey in `aws iam list-access-keys --user-name "$remUsername" --profile "$remProfile" --query 'AccessKeyMetadata[].[AccessKeyId]' --output text`;
                do
                    echo "Removing accesskey: $remAccesskey from user: $remUsername"
                    aws iam delete-access-key --user-name "$remUsername" --profile "$remProfile" --access-key-id "$remAccesskey"
                done;
        else echo "No access keys to be deleted from this user: $remUsername";
        fi;

    #Removing MFA devices attached to the user
    if [ $(aws iam list-mfa-devices --user-name "$remUsername" --profile "$remProfile" --query 'MFADevices[].[SerialNumber]' --output text | wc -l) -gt 0 ];
        then
            echo "Retrieve MFA serial number from the user: $remUsername";
                for remMFA in `aws iam list-mfa-devices --user-name "$remUsername" --profile "$remProfile" --query 'MFADevices[].[SerialNumber]' --output text`;
                    do
                    echo "Removing MFA device: $remMFA, attached to the user: $remUsername"
                    aws iam deactivate-mfa-device --user-name "$remUsername" --profile $remProfile --serial-number "$remMFA"
                done;
    else echo "No MFA is attached to this user: $remUsername";
    fi;

    #Removing Signing certificate
    if [ $(aws iam list-signing-certificates --user-name "$remUsername" --profile "$remProfile" --query 'Certificates[].[CertificateId]' --output text | wc -l) -gt 0 ];
        then
            for remCert in `aws iam list-signing-certificates --user-name "$remUsername" --profile "$remProfile" --query 'Certificates[].[CertificateId]' --output text`;
                do
                    echo "Removing user certificate: $remCert"
                    aws iam delete-signing-certificate --user-name "$remUsername" --profile "$remProfile" --certificate-id "$remCert"
            done
    else echo "No signing certificate is attached to this user: $remUsername";
    fi;

    #Removing SSH keys
    if [ $(aws iam list-ssh-public-keys --user-name "$remUsername" --profile "$remProfile" --query 'SSHPublicKeys[].[SSHPublicKeyId]' --output text | wc -l) -gt 0 ];
        then
            for remPubkey in `aws iam list-ssh-public-keys --user-name "$remUsername" --profile "$remProfile" --query 'SSHPublicKeys[].[SSHPublicKeyId]' --output text`;
                do
                    echo -e "Removing pubkey '$remPubkey'"
                    aws iam delete-ssh-public-key --user-name "$remUsername" --profile "$remProfile" --ssh-public-key-id "$remPubkey"
            done
    else echo "No SSH Key is attached to this user: $remUsername";
    fi;

    #Removing specific credentials
    if [ $(aws iam list-service-specific-credentials --user-name "$remUsername" --profile "$remProfile" --query 'ServiceSpecificCredentials[].[ServiceSpecificCredentialId]' --output text | wc -l) -gt 0 ];
        then
            for remSSC in `aws iam list-service-specific-credentials --user-name "$remUsername" --profile "$remProfile" --query 'ServiceSpecificCredentials[].[ServiceSpecificCredentialId]' --output text`;
                do
                    echo "Removing credentials: $remSSC"
                    aws iam delete-service-specific-credential --user-name "$remUsername" --profile "$remProfile" --service-specific-credential-id "$remSSC"
                done
    else echo "No CREDENTIALS is attached to this user: $remUsername";
    fi;

    #Removing IAM USer
    aws iam delete-user --user-name "$remUsername" --profile "$remProfile"

    if [ $(aws iam list-users --query 'Users[*].[UserName]' --output text --profile $remProfile | grep -ix $remUsername | wc -l) -eq 0 ];
        then
            echo "IAM account $remUsername has been deleted!";
    fi;

}


accessKeyVerificationFunction(){

    #Setting Paramaters
    akey_username="$1"
    akey_profile="$2"
    akey_expirydays="$3"
    akey_typenotify="$4"
    akey_MailEnvironment="$5"
    akey_MailAttachment="$6"
    akey_delaction="$7"
    akey_Recipient="$8"

    verChekingAccesskeys=`aws iam list-access-keys --user-name "$akey_username" --profile "$akey_profile" --query "AccessKeyMetadata[].AccessKeyId" --output text`

        if [[ -z $verChekingAccesskeys ]];
            then echo "No access keys for this user: $akey_username";
        else
            listAccessKey=`aws iam list-access-keys --user-name "$akey_username" --profile "$akey_profile" | jq -r '.AccessKeyMetadata[] | .AccessKeyId'`

            for key in $listAccessKey
                do
                    #Initializing loop variable
                    akey_createDate=""
                    akey_expiryInDays=""
                    akeyVer=""
                    # This is a validation statement if an existing access key ID is available or not
                    # If the key variable is null/empty, it means there are no existing access keys that is created in the account
                    if [[ -z $key ]];
                        then echo "No access key value.";
                    # Access keys that are within expiry date will received a notification reminder for rotation
                    # Failure to comply with the compliance team will immediately delete the existing access keys
                    else echo "Access key: $key will now be checked for compliance."
                        akey_ID=$key
                        akey_createDate=`aws iam list-access-keys --user-name "$akey_username" --profile "$akey_profile" | jq -r --arg KEY "$akey_ID" '.AccessKeyMetadata[] | select(.AccessKeyId==$KEY) |.CreateDate'`

                        akey_expiryInDays=$(expirydateFunction $akey_createDate $akey_expirydays);

                        akeyVer=$(expiryVerificationFunction "$akey_expiryInDays" "$akey_username" "$akey_expirydays" "$akey_createDate" $akey_typenotify "$akey_MailEnvironment" "$akey_MailAttachment" "$akey_profile" "$akey_delaction" "$akey_ID" "$akey_Recipient");
                        echo "$akeyVer"

                    fi;

                done
        fi;
}

expiryVerificationFunction(){

    #Setting parameters

    verExpiryInDays="$1"
    verUsername="$2"
    verComplianceExpiryDays="$3"
    verExpiryCheckDate="$4"
    verNotifAction="$5"
    verEnvironmentMailSubject="$6"
    verEmailAttachment="$7"
    verAWSProfile="$8"
    verIAMAction="$9"
    verAccessKeyID=${10}
    verRecipient=${11}

    # Validation if the expiry date is less than 16
    # The default value of verExpiryInDays is 1000, if the access key, expiration date is not yet expired.
    if [ "$verExpiryInDays" -lt 16 ];
        then echo "This account: $verUsername is breached compliance"

            # Validation if the expiry date is greater than 0
            # This separate the logic of the account if a notification reminder is needed to be sent or the delete function will be triggered.
            if [ "$verExpiryInDays" -gt 0 ];
                then
                    if [[ $(($verExpiryInDays % 3)) -eq 0 ]];
                        then
                        echo "Notification for access key expiration will be sent to this user: $verUsername.";
                        verExpiryDate=(`date -d $verExpiryCheckDate"+ $verComplianceExpiryDays days" +"%b-%d-%Y"`);
                        echo "This is currently calling caseNotificationFunction. The mail will be sent in this mail: $verRecipient";
                        expiryNotif=$(caseNotificationFunction "$verNotifAction" "$verAccessKeyID" "$verEnvironmentMailSubject" "$verEmailAttachment" "$verUsername" "$verExpiryDate" "$verExpiryInDays" "$verRecipient");
                        echo "$expiryNotify"
                    else echo "No notification will be sent to the user: $verUsername for now.";
                    fi;
            # Deletion of access keys or IAM account if the value is negative integer.
            else echo "This is now an expired account: $verUsername.";
                #echo "$verEnvironmentMailSubject" "$verExpiryInDays" "$verUsername" "$verAWSProfile" "$verIAMAction";

                expiryDelete=$(deleteFunction "$verExpiryDate" "$verEnvironmentMailSubject" "$verExpiryInDays" "$verUsername" "$verAWSProfile" "$verIAMAction" "$verAccessKeyID" "$verEmailAttachment" "$verRecipient");
                echo $expiryDelete
            fi;
    else echo "This is not an expired account.";
         echo "No notification will be sent to the user: $verUsername for now."
    fi;
}

#Function that determines the number of days before an account is expired.
expirydateFunction(){

    #Setting parameters
    gnucreateDate=(`date -d $1 +%s`)
    gnuexpireDate=(`date -d $1"+ $2 days" +%s`)
    gnucheckExpiry=(`date -d"+15 days" +%s`)
    gnudateToday=(`date +%s`)

    if [ "$gnucheckExpiry" -ge "$gnuexpireDate" ];
        then daysExpiry=$(((($gnuexpireDate-$gnudateToday))/86400));
            echo $daysExpiry;
    else daysExpiry=1000;
            echo $daysExpiry;
    fi

}

#Function that retrieve email and employee ID tags
serviceAccountVerificationFunction(){
    tags=`aws iam list-user-tags --user-name "$1" --profile "$2"`
    for c in {0..10}
    do
        saKey=$( jq -r  ".Tags[$c].Key" <<< "$tags" );
        if [ "$saKey" = "email" ];
            then saMailValue=$( jq -r  ".Tags[$c].Value" <<< "$tags" );
        elif [ "$saKey" = "employeeID" ];
            then saEmployeeID=$( jq -r  ".Tags[$c].Value" <<< "$tags" );
        fi;
    done
    echo $saEmployeeID $saMailValue

}

deleteFunction(){

    #Setting parameters
    delAccountExpiryDate="$1"
    delEnvironmentMailSubject="$2"
    delExpiryInDays="$3"
    delUsername="$4"
    delAWSProfile="$5"
    delIAMAction="$6"
    delAccessKeyId="$7"
    delEmailAttachment="$8"
    delRecipient="$9"
    delInfraGroup="IAM_IdleAccount_Exception"


    if [[  $delIAMAction == "user-access-password" ]];
        then echo "Disabling the AWS IAM User Account: $delUsername";

            #This is to send notification to user accounts that are not commpliant(Password age > 60 days)

            delNotifAction="DIUPC"
            if [ "$delExpiryInDays" -eq -1 ];
                then
                    echo "This is currently calling caseNotificationFunction. The mail will be sent in this mail: $delRecipient";
                    $(caseNotificationFunction "$delNotifAction" "NA" "$delEnvironmentMailSubject" "$delEmailAttachment" "$delUsername" "$delAccountExpiryDate" "$delExpiryInDays" "$delRecipient");
            else echo "Password reminder has already been sent to the user. No more action item is required."
            fi;


    elif [[ $delIAMAction = "user-access-inactive" ]];
        then echo "Disabling the AWS IAM User Account: $delUsername";

            #This is to delete accounts that are inactive(Inactivity > 90 days)
            delNotifAction="DIUI";
            delVerificationInfraGroup=`aws iam list-groups-for-user --user-name $delUsername --profile $delAWSProfile | jq -r --arg GROUP "$delInfraGroup" '.Groups[] | select(.GroupName==$GROUP) |.Arn'`
            if [[ -z "$delVerificationInfraGroup" ]];
                then

                    removalFunctionCall=$(removalFunction "$delAWSProfile" "$delUsername")
                    echo $removalFunctionCall
                    echo "This is currently calling caseNotificationFunction. The mail will be sent in this mail: $delRecipient";
                    $(caseNotificationFunction "$delNotifAction" "NA" "$delEnvironmentMailSubject" "$delEmailAttachment" "$delUsername" "$delAccountExpiryDate" "$delExpiryInDays" "$delRecipient");
            else echo "This $delUsername is part of the Infra Exception Group. There will be no action item required for this statement.";
            fi;


    elif [[ $delIAMAction = "access-key-deleted" ]];
        then echo "Removing active access key: $delAccessKeyId Username: $delUsername";
            #This is to delete access keys that are expired(Creation date > 60 days)
            delNotifAction="DAK";
            echo "This is currently calling caseNotificationFunction. The mail will be sent in this mail: $delRecipient";
            aws iam delete-access-key --access-key-id $delAccessKeyId --user-name $delUsername --profile $delAWSProfile;
            $(caseNotificationFunction "$delNotifAction" "$delAccessKeyId" "$delEnvironmentMailSubject" "$delEmailAttachment" "$delUsername" "$delAccountExpiryDate" "$delExpiryInDays" "$delRecipient");

    elif [[ $delIAMAction = "sa-access-key-notif" ]];
        then echo "Sending notification for the expired service account access key: $delAccessKeyId Username: $delUsername";
            #This is to send a reminder to escalation leads that the service account access key are expired(Creation date > 365 days)
            delNotifAction="EDAKSA";
            delRecipient="MatthewMumford@deltek.com,JuvenRobertoEdillor@deltek.com,ShaneAllen@deltek.com,CloudInfraSre@deltek.com"
                echo "This is currently calling caseNotificationFunction. The mail will be sent in this mail: $delRecipient";
            $(caseNotificationFunction "$delNotifAction" "$delAccessKeyId" "$delEnvironmentMailSubject" "$delEmailAttachment" "$delUsername" "$delAccountExpiryDate" "$delExpiryInDays" "$delRecipient");

    else echo "No action item is needed Username: $delUsername";
    fi;
}


caseNotificationFunction(){

    #Setting parameters
    notifAction="$1"
    notifAccessKeyId="$2"
    notifEnvironmentMailSubject="$3"
    notifEmailAttachment="$4"
    notifUsername="$5"
    notifAccountExpiryDate="$6"
    notifExpiryInDays="$7"
    recipient="$8"
    mailFrom="cloudnoreply@deltekfirst.com"
    mailRecipient=$recipient
    mailBodyPath="/Auto_Offboarding/IAM_Automation/exec2_mailbody.html"
    bccRepicient="MichaelDennisCresido@deltek.com"
    mailSubject=""


    if [ -f $mailBodyPath ];
        then rm $mailBodyPath;
    else echo "Do Nothing.";
    fi;
    sleep 0.5

    #This is an expiration reminder for access keys under SERVICE account
    if [[ $notifAction = "EDAKSA" ]];
     then echo "<html>
          <body style='font-family:calibri'>
               <h3>Hello, $notifUsername.</h3>
               <p>Your AWS IAM access key (Service Account) - $notifAccessKeyId in the $notifEnvironmentMailSubject environment is already expired.</p>
               <p>Please refer to these <a href='https://delteko365.sharepoint.com/:f:/s/PlatformSRE/Ei_t_KArURNJmygOwlFX3TgB3zRKLsiv65nYgOLOsbyikQ?e=O4W0Z6'>instructions</a> on how to rotate your access key. Failure to update your expiring access key will result to breach of compliance and is subject for escalation.</p>
               <p>For further assistance please contact Cloud Infra SRE team or submit a request in <a href='https://deltek.service-now.com/navpage.do'>Service Now</a><br>
               <p>Regards,<br>
               <a href='mailto:CloudInfraSRE@deltek.com'>Cloud Infrastructure SRE</a></p>
          </body>
        </html>" > $mailBodyPath;
        mailSubject="AWS IAM Access Key (Service Account) Expiration Notice"

    #This is a notification for deleted access keys
    elif [[ $notifAction = "DAK" ]]
     then echo "<html>
          <body style='font-family:calibri'>
               <h3>Hello, $notifUsername.</h3>
               <p>Your AWS IAM access key - $notifAccessKeyId in the $notifEnvironmentMailSubject environment has been deleted</p>
               <p>This is because your access key has reach its expiry date of 60 days.
               Please refer to these <a href='https://delteko365.sharepoint.com/:f:/s/PlatformSRE/Ei_t_KArURNJmygOwlFX3TgB3zRKLsiv65nYgOLOsbyikQ?e=O4W0Z6'>instructions</a> on how to rotate your access key.</p>
               <p>For further assistance please contact Cloud Infra SRE team or submit a request in <a href='https://deltek.service-now.com/navpage.do'>Service Now</a><br>
               <p>Regards,<br>
               <a href='mailto:CloudInfraSRE@deltek.com'>Cloud Infrastructure SRE</a></p>
          </body>
        </html>" > $mailBodyPath;
        mailSubject="AWS IAM Access Key Deletion Notice"

    #This is a notification for deleted USER account(Inactive)
    elif [[ $notifAction = "DIUI" ]]
      then echo "<html>
          <body style='font-family:calibri'>
               <h3>Hello, $notifUsername.</h3>
               <p>Your AWS IAM User account in the $notifEnvironmentMailSubject environment has been deleted.</p>
               <p>This is because your account has been inactive for 90 days.
               Please refer to these <a href='https://delteko365.sharepoint.com/:f:/s/PlatformSRE/Ei_t_KArURNJmygOwlFX3TgB3zRKLsiv65nYgOLOsbyikQ?e=O4W0Z6'>instructions</a> on how to re-enable your access.</p>
               <p>For further assistance please contact Cloud Infra SRE team or submit a request in <a href='https://deltek.service-now.com/navpage.do'>Service Now</a><br>
               <p>Regards,<br>
               <a href='mailto:CloudInfraSRE@deltek.com'>Cloud Infrastructure SRE</a></p>
          </body>
        </html>" > $mailBodyPath;
        mailSubject="AWS IAM User Account Deletion Notice"

    #This is a notification for USER account reminder (Non-compliant password)
    elif [[ $notifAction = "DIUPC" ]]
      then echo "<html>
          <body style='font-family:calibri'>
               <h3>Hello, $notifUsername.</h3>
               <p>The password for your IAM User Account in the $notifEnvironmentMailSubject environment has expired.</p>
               <p>To re-enable your access please kindly login to AWS Console and reset it.</p>
               <p>For further assistance please contact Cloud Infra SRE team or submit a request in <a href='https://deltek.service-now.com/navpage.do'>Service Now</a><br>
               <p>Regards,<br>
               <a href='mailto:CloudInfraSRE@deltek.com'>Cloud Infrastructure SRE</a></p>
          </body>
        </html>" > $mailBodyPath;
        mailSubject="AWS IAM User Expired Password Notice"

    #This is an expiration reminder for access keys under SERVICE account
    elif [[ $notifAction = "AKSAR" ]];
      then echo "<html>
          <body style='font-family:calibri'>
               <h3>Hello, $notifUsername.</h3>
               <p>Your AWS IAM access key (Service Account) - $notifAccessKeyId in the $notifEnvironmentMailSubject environment will be expiring in $notifExpiryInDays days.</p>
               <p>Please refer to these <a href='https://delteko365.sharepoint.com/:f:/s/PlatformSRE/Ei_t_KArURNJmygOwlFX3TgB3zRKLsiv65nYgOLOsbyikQ?e=O4W0Z6'>instructions</a> on how to rotate your access key. Failure to update your expiring access key before this date: $notifAccountExpiryDate, may subject for escalation.</p>
               <p>For further assistance please contact Cloud Infra SRE team or submit a request in <a href='https://deltek.service-now.com/navpage.do'>Service Now</a><br>
               <p>Regards,<br>
               <a href='mailto:CloudInfraSRE@deltek.com'>Cloud Infrastructure SRE</a></p>
          </body>
        </html>" > $mailBodyPath;
        mailSubject="AWS IAM Access Key (Service Account) Expiration Reminder"

    #This is an expiration reminder for access keys under USER account
    elif [[ $notifAction = "AKUAR" ]];
      then echo "<html>
          <body style='font-family:calibri'>
               <h3>Hello, $notifUsername.</h3>
               <p>Your AWS IAM access key - $notifAccessKeyId in the $notifEnvironmentMailSubject environment will be expiring in $notifExpiryInDays days.</p>
               Please refer to these <a href='https://delteko365.sharepoint.com/:f:/s/PlatformSRE/Ei_t_KArURNJmygOwlFX3TgB3zRKLsiv65nYgOLOsbyikQ?e=O4W0Z6'>instructions</a> on how to rotate your access key. Failure to update your expiring access key will result to its deletion by $notifAccountExpiryDate.</p>
               <p>For further assistance please contact Cloud Infra SRE team or submit a request in <a href='https://deltek.service-now.com/navpage.do'>Service Now</a><br>
               <p>Regards,<br>
               <a href='mailto:CloudInfraSRE@deltek.com'>Cloud Infrastructure SRE</a></p>
          </body>
        </html>" > $mailBodyPath;
        mailSubject="AWS IAM Access Key Expiration Reminder"

    #This is an expiration reminder for USER account that are not compliant
    elif [[ $notifAction = "UER" ]];
     then echo "<html>
          <body style='font-family:calibri'>
               <h3>Hello, $notifUsername.</h3>
               <p>The password for your IAM User Account in the $notifEnvironmentMailSubject environment will be expiring in $notifExpiryInDays days.</p>
               <p>You may reset your password by logging in your AWS Console Account.</p>
               <p>For further assistance please contact Cloud Infra SRE team or submit a request in <a href='https://deltek.service-now.com/navpage.do'>Service Now</a><br>
               <p>Regards,<br>
               <a href='mailto:CloudInfraSRE@deltek.com'>Cloud Infrastructure SRE</a></p>
          </body>
        </html>" > $mailBodyPath;
        mailSubject="AWS IAM User Account Password Expiration Reminder"

    #This is an expiration reminder for INACTIVE USER account
    elif [[ $notifAction = "UIR" ]];
     then echo "<html>
          <body style='font-family:calibri'>
               <h3>Hello, $notifUsername.</h3>
               <p>Your AWS IAM User Account in the $notifEnvironmentMailSubject environment is currently inactive.</p>
               <p>Your account will be deleted if you to fail to login by $notifAccountExpiryDate.</p>
               <p>For further assistance please contact Cloud Infra SRE team or submit a request in <a href='https://deltek.service-now.com/navpage.do'>Service Now</a><br>
               <p>Regards,<br>
               <a href='mailto:CloudInfraSRE@deltek.com'>Cloud Infrastructure SRE</a></p>
          </body>
        </html>" > $mailBodyPath;
        mailSubject="AWS IAM User Account Inactivity Reminder"

    else echo "No notif action has been saved.";
    fi;

sleep 1
( cat << MAIL; cat $mailBodyPath ) | sendmail -oi -t
From: ${mailFrom}
To: ${mailRecipient}
Subject: ${mailSubject}
Bcc: ${bccRepicient}
Content-Type: text/html

MAIL



}

caseEnvironmentFunction(){
    case "$mainProfile" in
   "flexplus-cli") echo "AWS FlexPlus - 363912313913"
   ;;
   "costpoint-cli") echo "AWS CostPoint - 389812532864"
   ;;
   "deltekdev-cli") echo "AWS DeltekDev - 343866166964"
   ;;
   "DCO-cli") echo "AWS DCO - 463061647317"
   ;;
   "GCE-cli") echo "AWS GCE - 391070432912"
   ;;
   "offsec-cli") echo "AWS OffSec - 361863686483"
   ;;
   "govwin-cli") echo "AWS GovWin - 645778329923"
   ;;
   "interspec-cli") echo "AWS InterSpec - 361336774414"
   ;;
   "especs-cli") echo "AWS Especs - 195464377553"
   ;;
   "arcom-cli") echo "AWS Arcom - 765750043360"
   ;;
   "sohnar-cli") echo "AWS Sohnar - 088838622944"
   ;;
   "sohnar01-cli") echo "AWS Sohnar01 - 503633531542"
   ;;
   "sohnar02-cli") echo "AWS Sohnar02 - 096801444263"
   ;;
   "sohnar03-cli") echo "AWS Sohnar03 - 844834612424"
   ;;
   "sohnar04-cli") echo "AWS Sohnar04 - 120998528415"
   ;;
   "sohnar05-cli") echo "AWS Sohnar05 - 048397503947"
   ;;
   "sohnar06-cli") echo "AWS Sohnar06 - 787694565324"
   ;;
   "sohnarWPP-cli") echo "AWS SohnarWPP - 089340555531"
   ;;
   "deltekea-cli") echo "AWS DeltekEA - 891599952938"
   ;;
   "onvia-cli") echo "AWS Onvia - 838221089058"
   ;;
   "govwindev-cli") echo "AWS GovWinDev - 656081332388"
   ;;
   "oss-cli") echo "AWS Global OSS - 364370348307"
   ;;
   "dcosecsandbox-cli") echo "AWS DCO Sec Sandbox - 931000889061"
   ;;
   "dcosandbox-cli") echo "DCO Sandbox - 312770088037"
   ;;
   "unionpoint-cli") echo "AWS EC Maconomy - 968610568229"
   ;;
   "dcoServiceBroker-cli") echo "AWS DCO Service Broker - 565237589376"
   ;;
esac
}

environmentLoopFunction(){

    dateToday=$(date '+%Y-%m-%d')
    filePath="/Auto_Offboarding/IAM_Automation/report/named-account-logs/$dateToday"
        if [ -d "$filePath" ];
            then echo "Folder is already currently existing.";

        else echo "Folder is not yet created."
            mkdir $filePath

        fi


    environmentArray=(deltekdev-cli costpoint-cli DCO-cli oss-cli sohnar01-cli flexplus-cli GCE-cli arcom-cli govwin-cli govwindev-cli dcosecsandbox-cli dcosandbox-cli dcoServiceBroker-cli offsec-cli interspec-cli deltekea-cli especs-cli sohnar-cli sohnar02-cli sohnar03-cli sohnar04-cli sohnar05-cli sohnar06-cli sohnarWPP-cli onvia-cli unionpoint-cli)
    #enviornmentArray=()
    for i in "${environmentArray[@]}";
        do
            #Initializing loop variable
            credsReport=""
            loopGenerateCredentialReport=""

            loopGenerateCredentialReport=`aws iam generate-credential-report --profile "$i"`
            sleep 60


            credsReport=`aws iam get-credential-report --profile "$i" 2>/dev/null`
            if [[ -z $credsReport ]];
             then echo "Skip this environment: $i";
            else
                csvPasswordFile="/Auto_Offboarding/IAM_Automation/report/AWS-IAM-PasswordInfo_$i.csv"
                rm -f $csvPasswordFile
                aws iam get-credential-report --query "Content" --output text --profile $i | base64 -d >> $csvPasswordFile
                mainFunction $i $filePath

                echo "Done executing this environment: $i";
            fi;
        done



}
environmentLoopFunction

                                                                            
                                                                                                           