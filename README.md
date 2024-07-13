# VPN Gate PKI

A simple public key infrastructure server aimed to manage OpenVPN credentials and configuration.
The intended application of this system can be seen from the following repository https://github.com/adityafarizki/vpn-manager-aws-infra, where this server is used as the vpn access manager.

## Basic features

- Auth integration with Google Workspace and Azure Entra ID.
- Generate user's vpn config as they log in and download.
- Revoke and reinstate user's access to the OpenVPN server.
- Use S3 or local filesystem as the storage and database.

## Environment Variables

- **OIDC_CLIENT_ID** string : client ID for this system from the OpenID Connect identity provider
- **OIDC_CLIENT_SECRET** string : client secret for this system from the OpenID Connect identity provider
- **OIDC_AUTH_URL** string : url to redirect to when authenticating with the OpenID Connect identity provider
- **OIDC_TOKEN_URL** string : url to fetch the access and id token from the identity provider
- **OIDC_CERT_URL** string : url to fetch either jwk or cert from the identity provider
- **OIDC_REDIRECT_URL** string : url to redirect from the identity provider, this is basically the base path of this server
- **OIDC_SCOPES** []string : comma delimited value specifying the scopes will be requested to the identity provider, sample "email,username,phone_number"
- **OIDC_PROVIDER** string : the name of the oidc provider to use, currently only "Google" and "AzureAD" are supported
- **STORAGE_BUCKET** string : name of the bucket that will be storing the user's cert and key
- **VPN_IP_ADDRESSES** []string : comma delimited value specifying the ip address and name for the ip address of the vpn instances, sample "vpn-singapore=23.123.32.21,vpn-tokyo=98.242.33.21"
- **ADMIN_EMAIL_LIST** []string optional : comma delimited value specifying which email addresses will have admin privileges, sample "person1@company.com,person2@company.com"
- **BASE_URL** string : base url of the deployed system. this value should refer to the main page of this system. sample: "https://vpn.personal.com"

- **PORT** string optional default:"8080" : port that will be used by the system
- **ADDRESS** string optional default:"0.0.0.0" : address to listen by the system
- **CA_BASE_DIR** string optional default:"ca" : base dir for the CA files
- **CLIENT_CERT_BASE_DIR** string optional default :"clients": base dir for the client cert files
- **USER_DATA_DIR_PATH** string optional default:"users" : base dir for the user files
- **CONFIG_BASE_DIR** string optional default:"ca" : base dir for the configuration files

## Contributing

### Reporting Bugs

If you find a bug, please create an issue with the following details:

- A clear and descriptive title
- A description of the steps to reproduce the issue
- Any error messages or logs
- Your environment (operating system, Go version, etc.)

### Requesting Features

If you have a feature request, please create an issue with the following details:

- A clear and descriptive title
- A detailed description of the feature
- Any examples or use cases

### Improving Documentation

If you find any errors in the documentation or have suggestions for improvements, feel free to create a pull request. Documentation is an important part of the project and we appreciate your contributions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
