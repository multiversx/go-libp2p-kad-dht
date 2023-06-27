package imports

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/ipfs/boxo/ipns"
	pb "github.com/ipfs/boxo/ipns/pb"
	"github.com/multiformats/go-multicodec"

	"github.com/gogo/protobuf/proto"
	logging "github.com/ipfs/go-log/v2"
	ipldcodec "github.com/ipld/go-ipld-prime/multicodec"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	record "github.com/libp2p/go-libp2p-record"
	ic "github.com/multiversx/go-libp2p/core/crypto"
	"github.com/multiversx/go-libp2p/core/peer"
	pstore "github.com/multiversx/go-libp2p/core/peerstore"
)

const (
	validity     = "Validity"
	validityType = "ValidityType"
	value        = "Value"
	sequence     = "Sequence"
	ttl          = "TTL"
)

var log = logging.Logger("ipns")

var _ record.Validator = Validator{}

// RecordKey returns the libp2p record key for a given peer ID.
func RecordKey(pid peer.ID) string {
	return "/ipns/" + string(pid)
}

// Validator is an IPNS record validator that satisfies the libp2p record
// validator interface.
type Validator struct {
	// KeyBook, if non-nil, will be used to lookup keys for validating IPNS
	// records.
	KeyBook pstore.KeyBook
}

// Validate validates an IPNS record.
func (v Validator) Validate(key string, value []byte) error {
	ns, pidString, err := record.SplitKey(key)
	if err != nil || ns != "ipns" {
		return ipns.ErrInvalidPath
	}

	// Parse the value into an IpnsEntry
	entry := new(pb.IpnsEntry)
	err = proto.Unmarshal(value, entry)
	if err != nil {
		return ipns.ErrBadRecord
	}

	// Get the public key defined by the ipns path
	pid, err := peer.IDFromBytes([]byte(pidString))
	if err != nil {
		log.Debugf("failed to parse ipns record key %s into peer ID", pidString)
		return ipns.ErrKeyFormat
	}

	pubk, err := v.getPublicKey(pid, entry)
	if err != nil {
		return err
	}

	return Validate(pubk, entry)
}

// ExtractPublicKey extracts a public key matching `pid` from the IPNS record,
// if possible.
//
// This function returns (nil, nil) when no public key can be extracted and
// nothing is malformed.
func ExtractPublicKey(pid peer.ID, entry *pb.IpnsEntry) (ic.PubKey, error) {
	if entry.PubKey != nil {
		pk, err := ic.UnmarshalPublicKey(entry.PubKey)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling pubkey in record: %s", err)
		}

		expPid, err := peer.IDFromPublicKey(pk)
		if err != nil {
			return nil, fmt.Errorf("could not regenerate peerID from pubkey: %s", err)
		}

		if pid != expPid {
			return nil, ipns.ErrPublicKeyMismatch
		}
		return pk, nil
	}

	return pid.ExtractPublicKey()
}

func (v Validator) getPublicKey(pid peer.ID, entry *pb.IpnsEntry) (ic.PubKey, error) {
	switch pk, err := ExtractPublicKey(pid, entry); err {
	case peer.ErrNoPublicKey:
	case nil:
		return pk, nil
	default:
		return nil, err
	}

	if v.KeyBook == nil {
		log.Debugf("public key with hash %s not found in IPNS record and no peer store provided", pid)
		return nil, ipns.ErrPublicKeyNotFound
	}

	pubk := v.KeyBook.PubKey(pid)
	if pubk == nil {
		log.Debugf("public key with hash %s not found in peer store", pid)
		return nil, ipns.ErrPublicKeyNotFound
	}
	return pubk, nil
}

// Select selects the best record by checking which has the highest sequence
// number and latest EOL.
//
// This function returns an error if any of the records fail to parse. Validate
// your records first!
func (v Validator) Select(k string, vals [][]byte) (int, error) {
	var recs []*pb.IpnsEntry
	for _, v := range vals {
		e := new(pb.IpnsEntry)
		if err := proto.Unmarshal(v, e); err != nil {
			return -1, err
		}
		recs = append(recs, e)
	}

	return selectRecord(recs, vals)
}

func selectRecord(recs []*pb.IpnsEntry, vals [][]byte) (int, error) {
	switch len(recs) {
	case 0:
		return -1, errors.New("no usable records in given set")
	case 1:
		return 0, nil
	}

	var i int
	for j := 1; j < len(recs); j++ {
		cmp, err := ipns.Compare(recs[i], recs[j])
		if err != nil {
			return -1, err
		}
		if cmp == 0 {
			cmp = bytes.Compare(vals[i], vals[j])
		}
		if cmp < 0 {
			i = j
		}
	}

	return i, nil
}

// Validates validates the given IPNS entry against the given public key.
func Validate(pk ic.PubKey, entry *pb.IpnsEntry) error {
	// Make sure max size is respected
	if entry.Size() > ipns.MaxRecordSize {
		return ipns.ErrRecordSize
	}

	// Check the ipns record signature with the public key
	if entry.GetSignatureV2() == nil {
		// always error if no valid signature could be found
		return ipns.ErrSignature
	}

	sig2Data, err := ipnsEntryDataForSigV2(entry)
	if err != nil {
		return fmt.Errorf("could not compute signature data: %w", err)
	}
	if ok, err := pk.Verify(sig2Data, entry.GetSignatureV2()); err != nil || !ok {
		return ipns.ErrSignature
	}

	// TODO: If we switch from pb.IpnsEntry to a more generic IpnsRecord type then perhaps we should only check
	// this if there is no v1 signature. In the meanwhile this helps avoid some potential rough edges around people
	// checking the entry fields instead of doing CBOR decoding everywhere.
	// See https://github.com/ipfs/boxo/ipns/pull/42 for next steps here
	if err := validateCborDataMatchesPbData(entry); err != nil {
		return err
	}

	eol, err := ipns.GetEOL(entry)
	if err != nil {
		return err
	}
	if time.Now().After(eol) {
		return ipns.ErrExpiredRecord
	}
	return nil
}

func ipnsEntryDataForSigV2(e *pb.IpnsEntry) ([]byte, error) {
	dataForSig := []byte("ipns-signature:")
	dataForSig = append(dataForSig, e.Data...)

	return dataForSig, nil
}

// TODO: Most of this function could probably be replaced with codegen
func validateCborDataMatchesPbData(entry *pb.IpnsEntry) error {
	if len(entry.GetData()) == 0 {
		return fmt.Errorf("record data is missing")
	}

	dec, err := ipldcodec.LookupDecoder(uint64(multicodec.DagCbor))
	if err != nil {
		return err
	}

	ndbuilder := basicnode.Prototype__Map{}.NewBuilder()
	if err := dec(ndbuilder, bytes.NewReader(entry.GetData())); err != nil {
		return err
	}

	fullNd := ndbuilder.Build()
	nd, err := fullNd.LookupByString(value)
	if err != nil {
		return err
	}
	ndBytes, err := nd.AsBytes()
	if err != nil {
		return err
	}
	if !bytes.Equal(entry.GetValue(), ndBytes) {
		return fmt.Errorf("field \"%v\" did not match between protobuf and CBOR", value)
	}

	nd, err = fullNd.LookupByString(validity)
	if err != nil {
		return err
	}
	ndBytes, err = nd.AsBytes()
	if err != nil {
		return err
	}
	if !bytes.Equal(entry.GetValidity(), ndBytes) {
		return fmt.Errorf("field \"%v\" did not match between protobuf and CBOR", validity)
	}

	nd, err = fullNd.LookupByString(validityType)
	if err != nil {
		return err
	}
	ndInt, err := nd.AsInt()
	if err != nil {
		return err
	}
	if int64(entry.GetValidityType()) != ndInt {
		return fmt.Errorf("field \"%v\" did not match between protobuf and CBOR", validityType)
	}

	nd, err = fullNd.LookupByString(sequence)
	if err != nil {
		return err
	}
	ndInt, err = nd.AsInt()
	if err != nil {
		return err
	}

	if entry.GetSequence() != uint64(ndInt) {
		return fmt.Errorf("field \"%v\" did not match between protobuf and CBOR", sequence)
	}

	nd, err = fullNd.LookupByString("TTL")
	if err != nil {
		return err
	}
	ndInt, err = nd.AsInt()
	if err != nil {
		return err
	}
	if entry.GetTtl() != uint64(ndInt) {
		return fmt.Errorf("field \"%v\" did not match between protobuf and CBOR", ttl)
	}

	return nil
}
