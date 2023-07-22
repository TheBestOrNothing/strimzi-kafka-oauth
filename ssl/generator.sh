
rm ca*
rm client*
rm server*

touch server.config
#echo 'subjectAltName=DNS:*.gitcoins.io,DNS:*.gitcoins.com,DNS:localhost,IP:0.0.0.0' > server.config
echo 'subjectAltName=DNS:ubuntu' > server.config

## Create your own Certificate Authority (CA)
# Generate a CA that is simply a public-private key pair and certificate, 
# and it is intended to sign other certificates.
openssl req -new -x509 -keyout ca-key -out ca-cert -days 365 \
	-subj "/CN=ubuntu" \
	-passout pass:ca-key-pass

# Add the generated CA to the clients’ truststore so that the clients can trust this CA
keytool -keystore client.truststore.jks -alias CARoot -importcert -file ca-cert \
	-storepass client-truststore-pass -trustcacerts -noprompt

# Add the generated CA to the brokers’ truststore so that the brokers can trust this CA
keytool -keystore server.truststore.jks -alias CARoot -importcert -file ca-cert \
	-storepass server-truststore-pass -trustcacerts -noprompt

############################## Gen Server keypairs #########################################
keytool -keystore server.keystore.jks -keyalg RSA -validity 365  \
	-genkey -dname "CN=ubuntu" \
	-alias localhost -storepass server-keystore-pass

# Please notice Due to a bug in OpenSSL, the x509 module will not copy requested extension fields 
# from CSRs into the final certificate. So the add the extension infomation to the server.config
# and use openssl -extfile to make sure the DNS, IP and other extension infomaiton added

# keytool -list -v -keystore server.keystore.jks -storepass server-keystore-pass

## Sign the server certificate with CA cert and key
# Export the certificate from the keystore
keytool -keystore server.keystore.jks -alias localhost -certreq -file server-cert-file \
	-storepass server-keystore-pass

# Sign it with the CA
openssl x509 -req -CA ca-cert -CAkey ca-key -in server-cert-file -out server-cert-signed \
	-days 365 -CAcreateserial -passin pass:ca-key-pass \
	-extfile server.config

# Import both the certificate of the CA and the signed server certificate into the broker keystore
keytool -keystore server.keystore.jks -alias CARoot -importcert -file ca-cert \
	-storepass server-keystore-pass -trustcacerts -noprompt
keytool -keystore server.keystore.jks -alias localhost -importcert -file server-cert-signed \
	-storepass server-keystore-pass -trustcacerts -noprompt


############################## Gen Client keypairs #########################################
keytool -keystore client.keystore.jks -keyalg RSA -validity 365  \
	-genkey -dname "CN=ubuntu" \
	-alias client -storepass client-keystore-pass 


# Export the certificate from the keystore
keytool -keystore client.keystore.jks -alias client -certreq -file client-cert-file \
	-storepass client-keystore-pass

# Sign it with the CA
openssl x509 -req -CA ca-cert -CAkey ca-key -in client-cert-file -out client-cert-signed \
	-days 365 -CAcreateserial -passin pass:ca-key-pass \
	-extfile server.config

# Import both the certificate of the CA and the signed client certificate into the client keystore
keytool -keystore client.keystore.jks -alias CARoot -importcert -file ca-cert \
	-storepass client-keystore-pass -trustcacerts -noprompt
keytool -keystore client.keystore.jks -alias client -importcert -file client-cert-signed \
	-storepass client-keystore-pass -trustcacerts -noprompt
