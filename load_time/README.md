# Load Test

It's called `load_time` because _test is a reserved file name ending for functionality test files in golang.

```shell
Usage: ./load_time -e|-d|-E|-D NUMBER -i INFILE
Load test for bulk encrypting/decrypting with the Ubiq service

  -h, -help               Show this help message and exit
  -V, -version            Show program's version number and exit

  -i, -in                 File to use containing cipher and plain text pairs
                            with datasets.
  -c CREDENTIALS, -creds CREDENTIALS
                          Set the file name with the API credentials
                            (default: ~/.ubiq/credentials)
  -P PROFILE, -profile PROFILE
                          Identify the profile within the credentials file

  OPTIONAL: For determining performance limits
  -e, -avgencrypt         Maximum average time in microseconds for encryption
  -d, -avgdecrypt         Maximum average time in microseconds for decryption
  -E, -maxencrypt         Maximum total time in microseconds for encryption
  -D, -maxdecrypt         Maximum total time in microseconds for decryption
```

## To Run
```shell
go build
./load_time -P {profile} -i {file} -e {avg encrypt} -d {avg decrypt} -E {total encrypt} -D {total decrypt}
```

JSON files in /DATA