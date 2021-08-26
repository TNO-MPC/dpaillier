// Copyright 2021 TNO
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dpaillier

// Package dpaillier implements a distributed Paillier encryption scheme based on
// Shamir secret sharing. The encryption scheme and protocols are described in
// https://eprint.iacr.org/2019/1136.
//
// Key generation is implemented as a protocol between all participants, consisting
// of multiple stages. Each stage consists of a state and a set of messages to be
// send to the other participants, and can be advanced to the next stage by feeding
// it messages from the other participants.
// Note that key generation is probabilistic and may fail. If it is successful, this
// process eventually results in a share of the private key, which must be used in
// the decryption protocol to decrypt messages.
//
// A regular Paillier public key can be derived from the private key, which can be
// used in the same way as regular Paillier public keys.

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/TNO-MPC/paillier"
	secret "github.com/TNO-MPC/shamir"
)

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

var random = rand.Reader

var ErrorBiprimalityTestFailed = errors.New("Probabilistic generation of bi-prime N failed. Restart the key generation protocol.")

type KeyGenerationParameters struct {
	// The number of total participants n in the protocol
	NumberOfParticipants int
	// The index of this participant (0 <= ParticipantIndex < NumberOfParticipants)
	ParticipantIndex int

	// The bit size kappa of the Paillier modulus N
	PaillierBitSize int

	// The degree t of the secret sharing polynomial
	// 2t + 1 participants are necessary
	SecretSharingDegree int
	// The statistical security parameter sigma of secret sharing over the integers
	SecretSharingStatisticalSecurity int
	// The secret sharing modulus prime P of bit size at least 2(kappa + log_2 n)
	SecretSharingModulus *big.Int

	// Number of times b to perform the biprimality check of N
	BiprimalityCheckTimes int
	// Number of parallel goroutines to use during the biprimality test
	NumProcessors int
}

// MarshalJSON returns a json representation of the key generation parameters.
// This is needed because otherwise the contained big.Int marshals as a float64,
// which loses precision.
func (params *KeyGenerationParameters) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	m["NumberOfParticipants"] = float64(params.NumberOfParticipants)
	m["ParticipantIndex"] = float64(params.ParticipantIndex)
	m["PaillierBitSize"] = float64(params.PaillierBitSize)
	m["SecretSharingDegree"] = float64(params.SecretSharingDegree)
	m["SecretSharingStatisticalSecurity"] = float64(params.SecretSharingStatisticalSecurity)
	m["SecretSharingModulus"] = params.SecretSharingModulus.String()
	m["BiprimalityCheckTimes"] = float64(params.BiprimalityCheckTimes)
	m["NumProcessors"] = float64(params.NumProcessors)
	return json.Marshal(m)
}

// Validate validates the given parameters. If an impossible situation is specified, an error is returned.
// Otherwise, any missing optional parameters are automatically added. The following parameters are optional:
//
// If SecretSharingDegree is omitted, the highest possible value for the given NumberOfParticipants is used.
//
// If SecretSharingStatisticalSecurity is omitted, it is set to 20.
//
// If SecretSharingModulus is omitted, a suitable one is randomly chosen.
//
// If BiprimalityCheckTimes is omitted, it is set to 100.
func (p *KeyGenerationParameters) Validate() error {
	if p.NumberOfParticipants < 3 {
		return fmt.Errorf("At least three participants are required (%d given)", p.NumberOfParticipants)
	}
	if p.ParticipantIndex < 0 || p.ParticipantIndex >= p.NumberOfParticipants {
		return fmt.Errorf("ParticipantIndex %d must be in [0, %d)", p.ParticipantIndex, p.NumberOfParticipants)
	}

	if p.SecretSharingDegree <= 0 {
		p.SecretSharingDegree = (p.NumberOfParticipants - 1) / 2
	}
	if p.SecretSharingDegree < 1 || 2*p.SecretSharingDegree+1 > p.NumberOfParticipants {
		return fmt.Errorf("SecretSharingDegree t must be positive, and 2t < n (t, n == %d, %d)", p.SecretSharingDegree, p.NumberOfParticipants)
	}

	if p.SecretSharingStatisticalSecurity <= 0 {
		p.SecretSharingStatisticalSecurity = 20
	}
	minPbitsize := 2 * (p.PaillierBitSize + int(math.Ceil(math.Log2(float64(p.NumberOfParticipants)))))
	if p.SecretSharingModulus == nil || p.SecretSharingModulus.Cmp(bigZero) <= 0 {
		var err error
		p.SecretSharingModulus, err = rand.Prime(rand.Reader, minPbitsize)
		if err != nil {
			return fmt.Errorf("Error generating SecretSharingModulus: %v", err)
		}
	} else if p.SecretSharingModulus.BitLen() < minPbitsize {
		return fmt.Errorf("SecretSharingModulus must have bit length at least 2(kappa + log_2 n) == %d, you specified %v", minPbitsize, p.SecretSharingModulus)
	}
	if p.BiprimalityCheckTimes <= 0 {
		p.BiprimalityCheckTimes = 100
	}
	if p.NumProcessors <= 0 {
		p.NumProcessors = 4
	}

	return nil
}

// Starts a new key generation protocol.
// This step generates random numbers pi and qi and secret shares these among the participants.
func NewKeyGenerationProtocol(params KeyGenerationParameters) (*KeyGenerationStage1, []*KeyGenerationMessage1, error) {
	// Generate two numbers p_i, q_i of bit size kappa
	max := big.NewInt(1)
	max.Lsh(max, uint(params.PaillierBitSize))
	pi, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, nil, fmt.Errorf("Random number generator error: %v", err)
	}
	qi, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, nil, fmt.Errorf("Random number generator error: %v", err)
	}

	// First player's pi, qi should be 3 mod 4, other players' should be 0 mod 4.
	var bitval uint = 0
	if params.ParticipantIndex == 0 {
		bitval = 1
	}

	pi.SetBit(pi, 0, bitval)
	pi.SetBit(pi, 1, bitval)
	qi.SetBit(qi, 0, bitval)
	qi.SetBit(qi, 1, bitval)

	// Create shares of pi and qi
	sharesOfP := secret.ShareFiniteField(pi, params.SecretSharingModulus, params.SecretSharingDegree, params.NumberOfParticipants)
	sharesOfQ := secret.ShareFiniteField(qi, params.SecretSharingModulus, params.SecretSharingDegree, params.NumberOfParticipants)

	// Create a share of zero to blind N
	sharesOf0 := secret.ShareFiniteField(big.NewInt(0), params.SecretSharingModulus, 2*params.SecretSharingDegree, params.NumberOfParticipants)

	// Distribute shares
	messages := make([]*KeyGenerationMessage1, 0, params.NumberOfParticipants-1)
	nextStage := &KeyGenerationStage1{
		Parameters: &params,
		TermOfP:    pi,
		TermOfQ:    qi,
	}
	for i := 0; i != params.NumberOfParticipants; i++ {
		m := &KeyGenerationMessage1{
			From:           params.ParticipantIndex,
			To:             i,
			ShareOfTermOfP: sharesOfP[i],
			ShareOfTermOfQ: sharesOfQ[i],
			ShareOfZero:    sharesOf0[i],
		}
		if i == params.ParticipantIndex {
			nextStage.MessageToSelf = m
		} else {
			messages = append(messages, m)
		}
	}
	return nextStage, messages, nil
}

type KeyGenerationMessage1 struct {
	From, To       int
	ShareOfTermOfP secret.Share
	ShareOfTermOfQ secret.Share
	ShareOfZero    secret.Share
}

type KeyGenerationStage1 struct {
	Parameters       *KeyGenerationParameters
	TermOfP, TermOfQ *big.Int
	MessageToSelf    *KeyGenerationMessage1
}

func (kgs *KeyGenerationStage1) Advance(messages []*KeyGenerationMessage1) (*KeyGenerationStage2, []*KeyGenerationMessage2, error) {
	// We now have all i'th shares of terms of P and Q. Add these together to form 'full' shares of P and Q
	sharesOfTermsOfP := make([]secret.Share, kgs.Parameters.NumberOfParticipants)
	sharesOfTermsOfQ := make([]secret.Share, kgs.Parameters.NumberOfParticipants)
	sharesOfZero := make([]secret.Share, kgs.Parameters.NumberOfParticipants)
	sharesOfTermsOfP[0] = kgs.MessageToSelf.ShareOfTermOfP
	sharesOfTermsOfQ[0] = kgs.MessageToSelf.ShareOfTermOfQ
	sharesOfZero[0] = kgs.MessageToSelf.ShareOfZero
	for i := range messages {
		sharesOfTermsOfP[i+1] = messages[i].ShareOfTermOfP
		sharesOfTermsOfQ[i+1] = messages[i].ShareOfTermOfQ
		sharesOfZero[i+1] = messages[i].ShareOfZero
	}
	shareOfP, err := secret.ShareAdd(sharesOfTermsOfP)
	if err != nil {
		return nil, nil, err
	}
	shareOfQ, err := secret.ShareAdd(sharesOfTermsOfQ)
	if err != nil {
		return nil, nil, err
	}

	// Multiply shares of P and Q to obtain a share of N
	shareOfN, err := secret.ShareMul([]secret.Share{shareOfP, shareOfQ})
	if err != nil {
		return nil, nil, err
	}

	// Add the shares of zero to blind N
	shareOfN, err = secret.ShareAdd(append(sharesOfZero, shareOfN))
	if err != nil {
		return nil, nil, err
	}

	// Distribute shares
	nextMessages := make([]*KeyGenerationMessage2, 0, kgs.Parameters.NumberOfParticipants-1)
	nextStage := &KeyGenerationStage2{
		Parameters: kgs.Parameters,
		TermOfP:    kgs.TermOfP,
		TermOfQ:    kgs.TermOfQ,
		ShareOfN:   shareOfN,
	}
	for i := 0; i != kgs.Parameters.NumberOfParticipants; i++ {
		if i != kgs.Parameters.ParticipantIndex {
			nextMessages = append(nextMessages, &KeyGenerationMessage2{
				From:     kgs.Parameters.ParticipantIndex,
				To:       i,
				ShareOfN: shareOfN,
			})
		}
	}
	return nextStage, nextMessages, nil
}

type KeyGenerationMessage2 struct {
	From, To int
	ShareOfN secret.Share
}

type KeyGenerationStage2 struct {
	Parameters       *KeyGenerationParameters
	TermOfP, TermOfQ *big.Int
	ShareOfN         secret.Share
}

func (kgs *KeyGenerationStage2) Advance(messages []*KeyGenerationMessage2) (*KeyGenerationStage3, []*KeyGenerationMessage3, error) {
	// Combine the shares of N. This should have the same result for everyone, which we check.
	sharesOfN := make([]secret.Share, kgs.Parameters.NumberOfParticipants)
	sharesOfN[0] = kgs.ShareOfN
	for i := range messages {
		sharesOfN[i+1] = messages[i].ShareOfN
	}
	N, err := secret.ShareCombine(sharesOfN)
	if err != nil {
		return nil, nil, err
	}

	// Party 1 is responsible for performing the small prime factor test
	if kgs.Parameters.ParticipantIndex == 1 {
		smallPrime := big.NewInt(0)
		for i := range SMALL_PRIMES {
			smallPrime.SetInt64(SMALL_PRIMES[i])
			if smallPrime.Mod(N, smallPrime).Cmp(bigZero) == 0 {
				return nil, nil, ErrorBiprimalityTestFailed
			}
		}
	}

	// Party 0 takes the initiative in the biprimality test, choosing BiprimalityCheckTimes elements
	// of the unit group of F_N.
	// Profiling reveals that the bulk of the work (85%) is in big.Jacobi for the entire protcool.
	// Therefore, use multiple goroutines.
	var testElements []*big.Int
	if kgs.Parameters.ParticipantIndex == 0 {
		// We check if N is divisible by 2 here - Jacobi panics if it is.
		bigTwo := big.NewInt(2)
		if bigTwo.Mod(N, bigTwo).Cmp(bigZero) == 0 {
			return nil, nil, ErrorBiprimalityTestFailed
		}

		testElements = make([]*big.Int, 0, kgs.Parameters.BiprimalityCheckTimes)

		dataCh := make(chan *big.Int)
		stopCh := make(chan struct{})

		for i := 0; i != kgs.Parameters.NumProcessors; i++ {
			go func() {
				for {
					// The try-receive operation is to try to exit the goroutine as early as
					// possible.
					select {
					case <-stopCh:
						return
					default:
					}

					g, err := rand.Int(rand.Reader, N)
					if err != nil || big.Jacobi(g, N) != 1 {
						continue
					}

					select {
					case <-stopCh:
						return
					case dataCh <- g:
					}
				}
			}()
		}

		for len(testElements) != kgs.Parameters.BiprimalityCheckTimes {
			testElements = append(testElements, <-dataCh)
		}
		close(stopCh)
	}

	// Prepare messages
	nextMessages := make([]*KeyGenerationMessage3, 0, kgs.Parameters.NumberOfParticipants-1)
	nextStage := &KeyGenerationStage3{
		Parameters:   kgs.Parameters,
		TermOfP:      kgs.TermOfP,
		TermOfQ:      kgs.TermOfQ,
		N:            N,
		TestElements: testElements,
	}
	for i := 0; i != kgs.Parameters.NumberOfParticipants; i++ {
		if i != kgs.Parameters.ParticipantIndex {
			m := &KeyGenerationMessage3{
				From:         kgs.Parameters.ParticipantIndex,
				To:           i,
				N:            N,
				TestElements: make([]*big.Int, len(testElements)),
			}
			for i := range testElements {
				m.TestElements[i] = big.NewInt(0).Set(testElements[i])
			}
			nextMessages = append(nextMessages, m)
		}
	}
	return nextStage, nextMessages, nil
}

type KeyGenerationMessage3 struct {
	From, To     int
	N            *big.Int
	TestElements []*big.Int
}

type KeyGenerationStage3 struct {
	Parameters       *KeyGenerationParameters
	TermOfP, TermOfQ *big.Int
	N                *big.Int
	TestElements     []*big.Int
}

func (kgs *KeyGenerationStage3) Advance(messages []*KeyGenerationMessage3) (*KeyGenerationStage4, []*KeyGenerationMessage4, error) {
	// Check if distributed generation of N was successful -- all the same answer?
	for i := range messages {
		if kgs.N.Cmp(messages[i].N) != 0 {
			return nil, nil, fmt.Errorf("Our value of N was different from that of party %d", i)
		}
	}

	// Collect the test elements from the messages
	testElements := kgs.TestElements
	for i := range messages {
		if messages[i].From == 0 {
			testElements = messages[i].TestElements
		}
	}
	if len(testElements) != kgs.Parameters.BiprimalityCheckTimes {
		return nil, nil, fmt.Errorf("Not enough test elements received (have %d, want %d)", len(testElements), kgs.Parameters.BiprimalityCheckTimes)
	}

	// Compute the test responses
	termOfLambda := big.NewInt(0)
	if kgs.Parameters.ParticipantIndex == 0 {
		termOfLambda.Set(kgs.N).Sub(termOfLambda, kgs.TermOfP).Sub(termOfLambda, kgs.TermOfQ).Add(termOfLambda, bigOne)
	} else {
		termOfLambda.Set(kgs.TermOfP).Add(termOfLambda, kgs.TermOfQ)
	}
	exponent := big.NewInt(4)
	exponent.Div(termOfLambda, exponent)
	for i := range testElements {
		testElements[i].Exp(testElements[i], exponent, kgs.N)
	}

	// Prepare messages
	nextMessages := make([]*KeyGenerationMessage4, 0, kgs.Parameters.NumberOfParticipants-1)
	nextStage := &KeyGenerationStage4{
		Parameters:   kgs.Parameters,
		N:            kgs.N,
		TermOfLambda: termOfLambda,
	}
	if kgs.Parameters.ParticipantIndex == 0 {
		nextStage.TestResponses = testElements
	}
	for i := 0; i != kgs.Parameters.NumberOfParticipants; i++ {
		if i != kgs.Parameters.ParticipantIndex {
			m := &KeyGenerationMessage4{
				From:          kgs.Parameters.ParticipantIndex,
				To:            i,
				TestResponses: testElements,
			}
			if kgs.Parameters.ParticipantIndex != 0 {
				m.TestResponses = testElements
			}
			nextMessages = append(nextMessages, m)
		}
	}
	return nextStage, nextMessages, nil
}

type KeyGenerationMessage4 struct {
	From, To      int
	TestResponses []*big.Int
}

type KeyGenerationStage4 struct {
	Parameters    *KeyGenerationParameters
	N             *big.Int
	TermOfLambda  *big.Int
	TestResponses []*big.Int
}

func (kgs *KeyGenerationStage4) Advance(messages []*KeyGenerationMessage4) (*KeyGenerationStage5, []*KeyGenerationMessage5, error) {
	// Final part of the biprimality test
	if kgs.Parameters.ParticipantIndex == 0 {
		// We check if testResponseFrom(0) == \pm \prod(i) testResponseFrom(i)
		// for each response, and if any are FALSE, then N is NOT bi-prime.
		// Multiply all other parties' test responses
		rightHand := big.NewInt(0)
		for i := 0; i != kgs.Parameters.BiprimalityCheckTimes; i++ {
			rightHand.Set(bigOne)
			for j := range messages {
				rightHand.Mul(rightHand, messages[j].TestResponses[i]).Mod(rightHand, kgs.N)
			}
			if kgs.TestResponses[i].Cmp(rightHand) == 0 {
				continue
			}
			rightHand.Neg(rightHand).Mod(rightHand, kgs.N)
			if kgs.TestResponses[i].Cmp(rightHand) == 0 {
				continue
			}
			return nil, nil, ErrorBiprimalityTestFailed
		}
	} else {
		// The term of lambda from the previous step is p_i + q_i, whereas player 0 has N - p0 - p0 + 1
		// If you want to get to N - p - q + 1 == (p-1)(q-1) == phi(N), you'll need to negate the pi and
		// qi for i > 0 before adding them!
		// (This is not necessary for the biprimality test, since there we just put the terms for i>0 on
		// the right-hand side, which is equivalent to negating them.)
		kgs.TermOfLambda.Neg(kgs.TermOfLambda)
	}

	// Create shares of li and bi
	termOfBeta, err := rand.Int(rand.Reader, kgs.N)
	if err != nil {
		return nil, nil, err
	}
	sharesOfTermOfL := secret.ShareIntegers(kgs.TermOfLambda, kgs.N, kgs.Parameters.SecretSharingStatisticalSecurity, kgs.Parameters.SecretSharingDegree, kgs.Parameters.NumberOfParticipants)
	sharesOfTermOfB := secret.ShareIntegers(termOfBeta, kgs.N, kgs.Parameters.SecretSharingStatisticalSecurity, kgs.Parameters.SecretSharingDegree, kgs.Parameters.NumberOfParticipants)

	// Distribute shares
	nextMessages := make([]*KeyGenerationMessage5, 0, kgs.Parameters.NumberOfParticipants-1)
	nextStage := &KeyGenerationStage5{
		Parameters: kgs.Parameters,
		N:          kgs.N,
		TermOfL:    kgs.TermOfLambda,
		TermOfB:    termOfBeta,
	}
	for i := 0; i != kgs.Parameters.NumberOfParticipants; i++ {
		m := &KeyGenerationMessage5{
			From:           kgs.Parameters.ParticipantIndex,
			To:             i,
			ShareOfTermOfL: sharesOfTermOfL[i],
			ShareOfTermOfB: sharesOfTermOfB[i],
		}
		if i == kgs.Parameters.ParticipantIndex {
			nextStage.MessageToSelf = m
		} else {
			nextMessages = append(nextMessages, m)
		}
	}
	return nextStage, nextMessages, nil
}

type KeyGenerationMessage5 struct {
	From, To                       int
	ShareOfTermOfL, ShareOfTermOfB secret.Share
}

type KeyGenerationStage5 struct {
	Parameters       *KeyGenerationParameters
	N                *big.Int
	TermOfL, TermOfB *big.Int
	MessageToSelf    *KeyGenerationMessage5
}

func (kgs *KeyGenerationStage5) Advance(messages []*KeyGenerationMessage5) (*KeyGenerationStage6, []*KeyGenerationMessage6, error) {
	// Generate private key share by combining all shares of lambda and beta
	sharesOfTermsOfL := []secret.Share{kgs.MessageToSelf.ShareOfTermOfL}
	sharesOfTermsOfB := []secret.Share{kgs.MessageToSelf.ShareOfTermOfB}
	for i := range messages {
		sharesOfTermsOfL = append(sharesOfTermsOfL, messages[i].ShareOfTermOfL)
		sharesOfTermsOfB = append(sharesOfTermsOfB, messages[i].ShareOfTermOfB)
	}
	shareOfL, err := secret.ShareAdd(sharesOfTermsOfL)
	if err != nil {
		return nil, nil, err
	}
	shareOfB, err := secret.ShareAdd(sharesOfTermsOfB)
	if err != nil {
		return nil, nil, err
	}

	// Multiply shares of lambda and beta to obtain a share of the private key, h(i)
	shareOfLB, err := secret.ShareMul([]secret.Share{shareOfL, shareOfB})
	if err != nil {
		return nil, nil, err
	}
	Hi := big.NewInt(0).Set(shareOfLB.Y)

	// We also compute the second part of the decryption key theta (though it's the same for everyone)
	// by transforming Hi into a Shamir secret share over N (though N is not prime...)
	shareOfLB.Y.Mod(shareOfLB.Y, kgs.N)
	shareOfLB.Factor = nil
	shareOfLB.FieldSize = kgs.N

	// Distribute shares
	nextMessages := make([]*KeyGenerationMessage6, 0, kgs.Parameters.NumberOfParticipants-1)
	nextStage := &KeyGenerationStage6{
		Parameters: kgs.Parameters,
		N:          kgs.N,
		I:          shareOfLB.X,
		Hi:         Hi,
	}
	for i := 0; i != kgs.Parameters.NumberOfParticipants; i++ {
		m := &KeyGenerationMessage6{
			From:         kgs.Parameters.ParticipantIndex,
			To:           i,
			ShareOfTheta: shareOfLB,
		}
		if i == kgs.Parameters.ParticipantIndex {
			nextStage.MessageToSelf = m
		} else {
			nextMessages = append(nextMessages, m)
		}
	}
	return nextStage, nextMessages, nil
}

type KeyGenerationMessage6 struct {
	From, To     int
	ShareOfTheta secret.Share
}

type KeyGenerationStage6 struct {
	Parameters    *KeyGenerationParameters
	N             *big.Int
	I             int
	Hi            *big.Int
	MessageToSelf *KeyGenerationMessage6
}

func (kgs *KeyGenerationStage6) Advance(messages []*KeyGenerationMessage6) (*PrivateKeyShare, error) {
	// Generate theta share by combining all shares of lambda and beta
	sharesOfTheta := []secret.Share{kgs.MessageToSelf.ShareOfTheta}
	for i := range messages {
		sharesOfTheta = append(sharesOfTheta, messages[i].ShareOfTheta)
	}
	ThetaInv, err := secret.ShareCombine(sharesOfTheta)
	if err != nil {
		return nil, err
	}
	if ThetaInv.ModInverse(ThetaInv, kgs.N) == nil {
		// Theta is a factor of N!
		return nil, ErrorBiprimalityTestFailed
	}

	return &PrivateKeyShare{
		PublicKey: paillier.PublicKey{
			N:      big.NewInt(0).Set(kgs.N),
			N2:     big.NewInt(0).Exp(kgs.N, big.NewInt(2), nil),
			Nplus1: big.NewInt(0).Add(kgs.N, bigOne),
		},
		ParticipantIndex: kgs.I,
		Hi:               kgs.Hi,
		ThetaInv:         ThetaInv,
		FactorialOfNPart: big.NewInt(0).MulRange(1, int64(kgs.Parameters.NumberOfParticipants)),
	}, nil
}
