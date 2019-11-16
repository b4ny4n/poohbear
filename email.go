package main

import (
    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/ses"
    "github.com/aws/aws-sdk-go/aws/awserr"
    "log"
    // "fmt"
    // "strings"
)

const (
    Subject = "Poohbear Honeypot Alert"
    CharSet = "UTF-8"
)

func SendEmail(message string, ac AlertConfig) {

    sess, err := session.NewSession(&aws.Config{
        Region:aws.String(ac.sesRegion)},
    )
    
    svc := ses.New(sess)
    
    input := &ses.SendEmailInput{
        Destination: &ses.Destination{
            CcAddresses: []*string{
            },
            ToAddresses: []*string{
                aws.String(ac.sesEmail),
            },
        },
        Message: &ses.Message{
            Body: &ses.Body{
                Html: &ses.Content{
                    Charset: aws.String(CharSet),
                    Data:    aws.String(message),
                },
                Text: &ses.Content{
                    Charset: aws.String(CharSet),
                    Data:    aws.String(message),
                },
            },
            Subject: &ses.Content{
                Charset: aws.String(CharSet),
                Data:    aws.String(Subject),
            },
        },
        Source: aws.String(ac.sesEmail),
    }

    // Attempt to send the email.
    result, err := svc.SendEmail(input)
    
    // Display error messages if they occur.
    if err != nil {
        if aerr, ok := err.(awserr.Error); ok {
            switch aerr.Code() {
            case ses.ErrCodeMessageRejected:
                log.Printf("%v: %v", ses.ErrCodeMessageRejected, aerr.Error())
            case ses.ErrCodeMailFromDomainNotVerifiedException:
                log.Printf("%v: %v", ses.ErrCodeMailFromDomainNotVerifiedException, aerr.Error())
            case ses.ErrCodeConfigurationSetDoesNotExistException:
                log.Printf("%v: %v", ses.ErrCodeConfigurationSetDoesNotExistException, aerr.Error())
            default:
                log.Printf("%v: %v", aerr.Error())
            }
        } else {
            // Print the error, cast err to awserr.Error to get the Code and
            // Message from an error.
            log.Printf("%v: %v", err.Error())
        }
    
        return
    }
    
    log.Printf("Email Sent to address: %v", ac.sesEmail)
    log.Printf("Result: %v", result)
}
