# Sample Email Files

This directory contains sample email files for testing the email analysis system.

## Available Samples

### Safe Emails
- `safe_email.eml` - Clean business email with no suspicious patterns
- `sample.eml` - Basic test email

### Suspicious Emails  
- `suspicious_email.eml` - Phishing attempt with urgency indicators
- `fiji_suspicious.eml` - International threat from Fiji domain
- `test_yara.eml` - Email designed to trigger YARA rules

## Expected Results

| File | Risk Level | Risk Score | ClamAV | YARA | Key Indicators |
|------|------------|------------|--------|------|----------------|
| safe_email.eml | SAFE | 0 | clean | clean | Business email, no suspicious patterns |
| sample.eml | SAFE | 0 | clean | clean | Basic test email |
| suspicious_email.eml | HIGH | 75 | clean | clean | Urgency, no-reply sender, personal info requests |
| fiji_suspicious.eml | HIGH | 100 | clean | clean | International domain, forwarded, multiple threats |
| test_yara.eml | HIGH | 100 | clean | clean | Multiple YARA rule triggers |

## Creating Your Own Samples

To create test emails:

1. **Safe Email Template**
   ```
   From: sender@company.com
   To: recipient@company.com
   Subject: Normal Business Subject
   Date: [current date]
   
   Normal business email content.
   ```

2. **Suspicious Email Template**
   ```
   From: noreply@suspicious-domain.fj
   To: user@example.com
   Subject: Fwd: URGENT - ACT NOW - Account Suspended
   Date: [current date]
   
   URGENT MESSAGE!
   
   Your account has been SUSPENDED.
   CLICK HERE to verify immediately.
   
   We need your personal information:
   - Social Security Number
   - Credit Card details
   ```

## Testing Guidelines

1. **Always test with safe emails first** to verify the system is working
2. **Use suspicious samples** to test threat detection
3. **Check both ClamAV and YARA results** for comprehensive analysis
4. **Verify risk scoring** matches expected levels
5. **Test database storage** by checking analysis history

## Security Note

These sample files are designed for testing purposes only. Do not use real personal information or actual malicious content in test emails.
