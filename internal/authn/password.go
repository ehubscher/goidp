package authn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

var hashFuncs = map[string]func(string) (string, error){
	"argon2id": generateArgon2idHash,
	"bcrypt":   generateBcryptHash,
}

var verifyFuncs = map[string]func(string, string) (bool, error){
	"argon2id": verifyArgon2idHash,
	"bcrypt":   verifyBcryptHash,
}

type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func GenerateHash(algo, password string) (encodedHash string, err error) {
	hashFunc, ok := hashFuncs[algo]
	if !ok {
		log.Fatalf("Algorithm %s is not supported.\n", algo)
	}

	return hashFunc(password)
}

func VerifyPassword(password, encodedHash string) (match bool, err error) {
	var vals []string = strings.Split(encodedHash, "$")
	if len(vals) > 2 {
		algo := vals[1]
		verifyFunc, ok := verifyFuncs[algo]
		if !ok {
			log.Fatalf("Algorithm %s is not supported.\n", algo)
		}

		return verifyFunc(password, encodedHash)
	}

	return false, nil
}

func configureArgon2id() (params argon2Params, err error) {
	memory, err := strconv.Atoi(os.Getenv("ARGON2ID_MEMORY"))
	if err != nil {
		log.Fatalf("Argon2id memory misconfigured: %v\n", err)
	}

	iterations, err := strconv.Atoi(os.Getenv("ARGON2ID_ITERATIONS"))
	if err != nil {
		log.Fatalf("Argon2id iterations misconfigured: %v\n", err)
	}

	parallelism, err := strconv.Atoi(os.Getenv("ARGON2ID_PARALLELISM"))
	if err != nil {
		log.Fatalf("Argon2id parallelism misconfigured: %v\n", err)
	}

	saltLength, err := strconv.Atoi(os.Getenv("ARGON2ID_SALT_LENGTH"))
	if err != nil {
		log.Fatalf("Argon2id salt length misconfigured: %v\n", err)
	}

	keyLength, err := strconv.Atoi(os.Getenv("ARGON2ID_KEY_LENGTH"))
	if err != nil {
		log.Fatalf("Argon2id key length misconfigured: %v\n", err)
	}

	return argon2Params{
		memory:      uint32(memory),
		iterations:  uint32(iterations),
		parallelism: uint8(parallelism),
		saltLength:  uint32(saltLength),
		keyLength:   uint32(keyLength),
	}, nil
}

func configureBcrypt() (cost int, err error) {
	cost, err = strconv.Atoi(os.Getenv("BCRYPT_COST"))
	if err != nil {
		slog.Error("Bcrypt cost misconfigured.", "err", err)
		log.Fatalf("Bcrypt cost misconfigured. %v", err)
	}

	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		slog.Error(bcrypt.InvalidCostError(cost).Error())
		log.Fatal(bcrypt.InvalidCostError(cost).Error())
	}

	return int(cost), nil
}

func decodeArgon2idHash(encodedHash string) (params argon2Params, salt, hash []byte, err error) {
	var vals []string = strings.Split(encodedHash, "$")
	if len(vals) != 5 {
		return argon2Params{}, []byte{}, []byte{}, errors.New("invalid encoding on hash")
	}

	var opts []string = strings.Split(vals[2], ",")
	if len(opts) != 4 {
		return argon2Params{}, []byte{}, []byte{}, errors.New("invalid options encoding on hash")
	}

	var version int
	params = argon2Params{}
	_, err = fmt.Sscanf(
		vals[2],
		"v=%d,m=%d,t=%d,p=%d",
		&version,
		&params.memory,
		&params.iterations,
		&params.parallelism,
	)
	if err != nil {
		return params, []byte{}, []byte{}, err
	}
	if version != argon2.Version {
		return argon2Params{}, []byte{}, []byte{}, errors.New("incompatible Argon2 version")
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[3])
	if err != nil {
		return params, salt, []byte{}, err
	}
	params.saltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return params, salt, []byte{}, err
	}
	params.keyLength = uint32(len(hash))

	return params, salt, hash, nil
}

func decodeBcryptHash(encodedHash string) (hash []byte, err error) {
	var vals []string = strings.Split(encodedHash, "$")
	if len(vals) != 4 {
		slog.Error("Invalid encoding on string for bcrypt format.", "err", err)
		return []byte{}, err
	}

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[3])
	if err != nil {
		slog.Error("Problem decoding base64 encoded string.", "err", err)
		return []byte{}, err
	}

	return hash, nil
}

func generateArgon2idHash(password string) (encodedHash string, err error) {
	params, err := configureArgon2id()
	if err != nil {
		log.Fatalf("Argon2id memory misconfigured: %v\n", err)
	}

	// Generate a cryptographically secure random salt.
	salt := make([]byte, params.saltLength)
	_, err = rand.Read(salt)
	if err != nil {
		return "", err
	}

	// This will generate a hash of the password using the Argon2id variant.
	var hash []byte = argon2.IDKey(
		[]byte(password),
		salt,
		params.iterations,
		params.memory,
		params.parallelism,
		params.keyLength,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash = fmt.Sprintf(
		"$argon2id$v=%d,m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.memory,
		params.iterations,
		params.parallelism,
		b64Salt,
		b64Hash,
	)

	return encodedHash, nil
}

func generateBcryptHash(password string) (encodedHash string, err error) {
	cost, err := configureBcrypt()
	if err != nil {
		log.Fatalf("Bcrypt memory misconfigured: %v\n", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		slog.Error("Problem generating hash.", "err", err)
		log.Fatal(err)
	}

	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	encodedHash = fmt.Sprintf("$bcrypt$c=%d$%s", cost, b64Hash)

	return encodedHash, nil
}

func verifyArgon2idHash(password, encodedHash string) (match bool, err error) {
	params, salt, hash, err := decodeArgon2idHash(encodedHash)
	if err != nil {
		log.Fatal(err)
	}

	// Derive the key from the other password using the same parameters.
	var verification []byte = argon2.IDKey(
		[]byte(password),
		salt,
		params.iterations,
		params.memory,
		params.parallelism,
		params.keyLength,
	)

	// Check that the contents of the hashed passwords are identical.
	// Note that we are using the subtle.ConstantTimeCompare() function for this
	// to help prevent timing attacks.
	if subtle.ConstantTimeCompare(hash, verification) == 1 {
		return true, nil
	}

	return false, errors.New("invalid password")
}

func verifyBcryptHash(password, encodedHash string) (match bool, err error) {
	hash, err := decodeBcryptHash(encodedHash)
	if err != nil {
		slog.Error("Problems decoding base64 encoded bcrypt string.", "err", err)
	}

	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
	if err != nil {
		slog.Error("Invalid password.", "err", err)
		return false, err
	}

	return true, nil
}
