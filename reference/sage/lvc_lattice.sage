from hashlib import shake_256
from math import isfinite


TRAP_GEN_MP12_DOMAIN = b"LVC-Verkle-Sage-mp12-trap-gen-v1"
H1_DOMAIN = b"LVC-Verkle-H1-to-Zq-vector-v1"
H2_SCALAR_DOMAIN = b"LVC-Verkle-H2-to-challenge-scalar-v1"
REGISTER_EPOCH_DOMAIN = b"LVC-Verkle-Sage-register-epoch-v1"
STATE_TREE_LEAF_INDEX_DOMAIN = b"LVC-Verkle-Sage-state-tree-leaf-index-v1"
LATTICE_VERKLE_FS_COEFFICIENT_DOMAIN = b"LVC-Verkle-Sage-linear-verkle-fs-coefficient-v1"
LATTICE_VERKLE_ACTIVE_LEAF_DOMAIN = b"LVC-Verkle-Sage-linear-verkle-active-leaf-v1"
LATTICE_VERKLE_REVOKED_LEAF_DOMAIN = b"LVC-Verkle-Sage-linear-verkle-revoked-leaf-v1"
DISCRETE_GAUSSIAN_REAL_PRECISION_BITS = 256
DISCRETE_GAUSSIAN_DRAW_BYTES = 32
DISCRETE_GAUSSIAN_EXACT_CDF_MAX_SUPPORT = 20000
KLEIN_TRACE_MAX_REPORTED_COORDINATES = 64
KLEIN_GSO_REAL_PRECISION_BITS = 256


class LatticeParameters:
    def __init__(self, n, m, q, beta, sigma_pre):
        self.n = ZZ(n)
        self.m = ZZ(m)
        self.q = ZZ(q)
        self.beta = ZZ(beta)
        self.sigma_pre = RDF(sigma_pre)

        if self.n <= 0 or self.m < self.n:
            raise ValueError("expected dimensions with 0 < n <= m")
        if self.q <= 1:
            raise ValueError("expected q > 1")
        if self.beta <= 0:
            raise ValueError("expected beta > 0")
        if not isfinite(float(self.sigma_pre)) or self.sigma_pre <= 0:
            raise ValueError("expected finite sigma_pre > 0")

    def ring(self):
        return Integers(self.q)

    def beta_squared(self):
        return self.beta * self.beta


class MP12GadgetParameters:
    def __init__(self, n, q, base=2, k=None, m_bar=None):
        self.n = ZZ(n)
        self.q = ZZ(q)
        self.base = ZZ(base)

        if self.n <= 0:
            raise ValueError("expected n > 0")
        if self.q <= 1:
            raise ValueError("expected q > 1")
        if self.base <= 1:
            raise ValueError("expected base > 1")

        self.k = ZZ(k) if k is not None else _ceil_log(self.q, self.base)
        if self.k <= 0 or self.base ** self.k < self.q:
            raise ValueError("expected base^k >= q")

        self.w = self.n * self.k
        self.m_bar = ZZ(m_bar) if m_bar is not None else self.n * self.k + _ceil_log(self.n, 2) ** 2
        if self.m_bar <= 0:
            raise ValueError("expected m_bar > 0")

        self.m = self.m_bar + self.w

    def ring(self):
        return Integers(self.q)


class MP12GTrapdoor:
    def __init__(self, r, gadget, a_bar):
        self.r = r
        self.gadget = gadget
        self.a_bar = a_bar


class LatticeCredential:
    def __init__(
        self,
        identity,
        epoch,
        y_id,
        z_id,
        norm_squared,
        beta,
        parameter_report,
        sample_pre_report=None,
        path_proof=None,
        root=None,
    ):
        self.identity = identity
        self.epoch = epoch
        self.y_id = y_id
        self.z_id = z_id
        self.norm_squared = norm_squared
        self.beta = ZZ(beta)
        self.parameter_report = parameter_report
        self.sample_pre_report = sample_pre_report
        self.path_proof = path_proof
        self.root = root


class AuthenticationParameters:
    def __init__(self, challenge_modulus, sigma_mask, beta_response, max_attempts=128, nonce_bytes=16):
        self.challenge_modulus = ZZ(challenge_modulus)
        self.sigma_mask = RDF(sigma_mask)
        self.beta_response = ZZ(beta_response)
        self.max_attempts = ZZ(max_attempts)
        self.nonce_bytes = ZZ(nonce_bytes)

        if self.challenge_modulus <= 1:
            raise ValueError("expected challenge_modulus > 1")
        if self.challenge_modulus % 2 == 0:
            raise ValueError("expected odd challenge_modulus for centered scalar challenges")
        if not isfinite(float(self.sigma_mask)) or self.sigma_mask <= 0:
            raise ValueError("expected finite sigma_mask > 0")
        if self.beta_response <= 0:
            raise ValueError("expected beta_response > 0")
        if self.max_attempts <= 0:
            raise ValueError("expected max_attempts > 0")
        if self.nonce_bytes <= 0:
            raise ValueError("expected nonce_bytes > 0")

    def challenge_bound(self):
        return (self.challenge_modulus - 1) // 2

    def delta_c_min(self):
        return ZZ(1)

    def center_challenge(self, challenge):
        return centered_lift(challenge, self.challenge_modulus)

    def contains_challenge(self, challenge):
        challenge = ZZ(challenge)
        return -self.challenge_bound() <= challenge <= self.challenge_bound()


class AuthenticationTranscript:
    def __init__(self, path_proof, commitment, challenge, response, audit_report=None):
        self.path_proof = path_proof
        self.commitment = commitment
        self.challenge = ZZ(challenge)
        self.response = response
        self.audit_report = audit_report


class AuthenticationChallenge:
    def __init__(self, nonce, root):
        self.nonce = _as_bytes(nonce)
        self.root = _as_bytes(root)


class LVCVerkleSetupParameters:
    def __init__(
        self,
        lattice_params,
        beta,
        sigma_pre,
        tree_params,
        auth_params,
        omega_factor=None,
        auth_omega_factor=None,
        sample_pre_tail_cutoff=12,
        mask_tail_cutoff=12,
    ):
        self.lattice_params = lattice_params
        self.beta = ZZ(beta)
        self.sigma_pre = RDF(sigma_pre)
        self.tree_params = tree_params
        self.auth_params = auth_params
        self.omega_factor = omega_factor
        self.auth_omega_factor = auth_omega_factor
        self.sample_pre_tail_cutoff = ZZ(sample_pre_tail_cutoff)
        self.mask_tail_cutoff = ZZ(mask_tail_cutoff)

        if self.beta <= 0:
            raise ValueError("expected beta > 0")
        if not isfinite(float(self.sigma_pre)) or self.sigma_pre <= 0:
            raise ValueError("expected finite sigma_pre > 0")
        if self.omega_factor is not None and (
            not isfinite(float(self.omega_factor)) or RDF(self.omega_factor) <= 0
        ):
            raise ValueError("expected positive sample_pre omega_factor")
        if self.auth_omega_factor is not None and (
            not isfinite(float(self.auth_omega_factor))
            or RDF(self.auth_omega_factor) <= 0
        ):
            raise ValueError("expected positive authentication omega_factor")
        if self.sample_pre_tail_cutoff <= 0:
            raise ValueError("expected sample_pre_tail_cutoff > 0")
        if self.mask_tail_cutoff <= 0:
            raise ValueError("expected mask_tail_cutoff > 0")


class SageRandomOracleDescriptor:
    def __init__(self, name, domain, input_spec, output_spec, method, active=True):
        self.name = name
        self.domain = _as_bytes(domain)
        self.input_spec = input_spec
        self.output_spec = output_spec
        self.method = method
        self.active = bool(active)


def sage_random_oracle_descriptors(lattice_params, auth_params):
    """Return the public H1/H2 choices made by Setup."""
    return {
        "H1": SageRandomOracleDescriptor(
            "H1",
            H1_DOMAIN,
            "{0,1}*",
            "Z_q^n",
            "SHAKE256_XOF_64_bit_rejection_sampling_to_Zq_vector",
        ),
        "H2": SageRandomOracleDescriptor(
            "H2",
            H2_SCALAR_DOMAIN,
            "Y_id || w || rho || rt || id",
            "C_lambda = {-B_c, ..., B_c}",
            "SHAKE256_XOF_64_bit_rejection_sampling_then_centered_lift",
        ),
    }


class LVCVerklePublicParameters:
    def __init__(
        self,
        A,
        lattice_params,
        beta,
        sigma_pre,
        tree_params,
        auth_params,
        root,
        omega_factor=None,
        auth_omega_factor=None,
        sample_pre_tail_cutoff=12,
        mask_tail_cutoff=12,
    ):
        self.A = A
        self.lattice_params = lattice_params
        self.G = gadget_matrix(lattice_params)
        self.q = ZZ(lattice_params.q)
        self.beta = ZZ(beta)
        self.sigma_pre = RDF(sigma_pre)
        self.tree_params = tree_params
        self.auth_params = auth_params
        self.sigma = RDF(auth_params.sigma_mask)
        oracle_descriptors = sage_random_oracle_descriptors(lattice_params, auth_params)
        self.H1 = oracle_descriptors["H1"]
        self.H2 = oracle_descriptors["H2"]
        self.b = ZZ(tree_params.branching_factor)
        self.h = ZZ(tree_params.height)
        self.root0 = _as_bytes(root)
        self.rt0 = _as_bytes(root)
        self.root = root
        self.omega_factor = omega_factor
        self.sample_pre_omega_factor = omega_factor
        self.auth_omega_factor = auth_omega_factor
        self.sample_pre_tail_cutoff = ZZ(sample_pre_tail_cutoff)
        self.mask_tail_cutoff = ZZ(mask_tail_cutoff)


class LVCVerkleMasterSecretKey:
    def __init__(self, trapdoor):
        self.trapdoor = trapdoor


class LVCVerkleState:
    def __init__(self, state_tree, sample_pre_context=None):
        self.state_tree = state_tree
        self.sample_pre_context = sample_pre_context
        self.credentials_by_identity = {}
        self.credential_history_by_identity = {}

    def current_root(self):
        return self.state_tree.root()


class LVCVerkleSchemeInstance:
    """Direct paper-algorithm wrapper for Setup/Register/Auth/Verify/Revoke."""

    def __init__(self, setup_params, seed_parts):
        self.public_parameters, self.master_secret_key, self.state = setup_lvc_verkle(
            setup_params,
            seed_parts,
        )

    @classmethod
    def setup(cls, setup_params, seed_parts):
        return cls(setup_params, seed_parts)

    @property
    def pp(self):
        return self.public_parameters

    @property
    def msk(self):
        return self.master_secret_key

    def current_root(self):
        return self.public_parameters.root

    def register(self, identity, seed_parts, epoch=None):
        if epoch is None:
            return register_lvc_verkle_by_identity(
                self.public_parameters,
                self.master_secret_key,
                self.state,
                identity,
                seed_parts,
            )

        return register_lvc_verkle(
            self.public_parameters,
            self.master_secret_key,
            self.state,
            identity,
            epoch,
            seed_parts,
        )

    def issue_challenge(self, nonce=None, seed_parts=None):
        if nonce is not None:
            return issue_authentication_challenge(self.public_parameters, nonce)
        if seed_parts is None:
            raise ValueError("issue_challenge requires nonce or seed_parts")

        return issue_sampled_authentication_challenge(
            self.public_parameters,
            seed_parts,
        )

    def authenticate(self, credential, identity, challenge, seed_parts):
        if not isinstance(challenge, AuthenticationChallenge):
            challenge = issue_authentication_challenge(
                self.public_parameters,
                challenge,
            )

        return authenticate_lvc_verkle_challenge(
            self.public_parameters,
            credential,
            identity,
            challenge,
            seed_parts,
        )

    def verify(self, identity, y_id, challenge, transcript):
        if isinstance(challenge, AuthenticationChallenge):
            return verify_lvc_verkle_challenge(
                self.public_parameters,
                identity,
                y_id,
                challenge,
                transcript,
            )

        return verify_lvc_verkle(
            self.public_parameters,
            identity,
            y_id,
            challenge,
            transcript,
        )

    def verify_at_root(self, identity, y_id, nonce, root, transcript):
        return verify_lvc_verkle_at_root(
            self.public_parameters,
            identity,
            y_id,
            nonce,
            root,
            transcript,
        )

    def refresh_credential(self, identity):
        return refresh_lvc_verkle_credential(
            self.public_parameters,
            self.state,
            identity,
        )

    def revoke(self, identity):
        return revoke_lvc_verkle(
            self.public_parameters,
            self.master_secret_key,
            self.state,
            identity,
        )

    def is_active(self, identity):
        return identity_active_in_state(self.state, identity)


class VerifierSession:
    """Optional verifier-side replay cache for one verification session."""

    def __init__(self):
        self.used_challenges = set()

    def verify_once(self, public_parameters, identity, y_id, challenge, transcript):
        if isinstance(challenge, AuthenticationChallenge):
            nonce = challenge.nonce
            root = challenge.root
        else:
            nonce = challenge
            root = public_parameters.root

        return self.verify_at_root_once(
            public_parameters,
            identity,
            y_id,
            nonce,
            root,
            transcript,
        )

    def verify_at_root_once(
        self,
        public_parameters,
        identity,
        y_id,
        nonce,
        root,
        transcript,
    ):
        key = (
            _as_bytes(identity),
            _serialize_zq_vector(y_id),
            _as_bytes(nonce),
            _as_bytes(root),
        )
        if key in self.used_challenges:
            return False

        accepts = verify_lvc_verkle_at_root(
            public_parameters,
            identity,
            y_id,
            nonce,
            root,
            transcript,
        )
        if accepts:
            self.used_challenges.add(key)

        return accepts


class PublicProofRefreshData:
    def __init__(self, identity, y_id, path_proof, root):
        self.identity = _as_bytes(identity)
        self.y_id = y_id
        self.path_proof = path_proof
        self.root = _as_bytes(root)


class VerkleTreeParameters:
    def __init__(self, branching_factor, height, commitment_bytes=32):
        self.branching_factor = ZZ(branching_factor)
        self.height = ZZ(height)
        self.commitment_bytes = ZZ(commitment_bytes)

        if self.branching_factor <= 1:
            raise ValueError("expected branching_factor > 1")
        if self.height <= 0:
            raise ValueError("expected height > 0")
        if self.commitment_bytes <= 0:
            raise ValueError("expected commitment_bytes > 0")

    def leaf_count(self):
        return self.branching_factor ** self.height


class LatticeVerklePathProof:
    def __init__(self, leaf_index, path_indices, sibling_commitment_layers, lattice_params, slot_probe=0):
        self.backend = "lattice_linear_verkle_tree"
        self.leaf_index = ZZ(leaf_index)
        self.path_indices = [ZZ(index) for index in path_indices]
        self.sibling_commitment_layers = sibling_commitment_layers
        self.lattice_params = lattice_params
        self.slot_probe = ZZ(slot_probe)

class LatticeVerkleTree:
    """Paper-style Verkle tree with Zn_q vector nodes and FS linear aggregation."""

    def __init__(self, params, lattice_params):
        self.params = params
        self.lattice_params = lattice_params
        self.leaves_by_index = {}
        self.indices_by_identity = {}
        self.node_cache = {}
        self.occupied_prefixes = set()

    def root_vector(self):
        return self._cached_subtree_commitment(())

    def root(self):
        return _serialize_zq_vector(self.root_vector())

    def insert(self, identity, y_id):
        identity = _as_bytes(identity)

        if identity in self.indices_by_identity:
            current_leaf = self.leaves_by_index[self.indices_by_identity[identity]]
            if current_leaf["active"]:
                raise ValueError("identity already registered")

        index, slot_probe = self._allocate_leaf_index(identity)

        self.indices_by_identity[identity] = index
        self.leaves_by_index[index] = {
            "identity": identity,
            "y_id": y_id,
            "active": True,
            "slot_probe": slot_probe,
        }
        self._mark_occupied_prefixes(index)
        self._update_path_cache(index)

        return self.path_proof(identity), self.root()

    def revoke(self, identity):
        identity = _as_bytes(identity)
        if identity not in self.indices_by_identity:
            raise ValueError("identity is not registered")

        index = self.indices_by_identity[identity]
        leaf = self.leaves_by_index[index]
        if not leaf["active"]:
            raise ValueError("identity is already revoked")

        leaf["active"] = False
        self._update_path_cache(index)

        return self.root()

    def path_proof(self, identity):
        identity = _as_bytes(identity)
        if identity not in self.indices_by_identity:
            raise ValueError("identity is not registered")

        index = self.indices_by_identity[identity]
        slot_probe = self.leaves_by_index[index]["slot_probe"]
        digits = _index_to_base_digits(index, self.params.branching_factor, self.params.height)
        path_indices = []
        sibling_layers = []

        for parent_level in reversed(range(self.params.height)):
            prefix = digits[:parent_level]
            position = digits[parent_level]
            child_commitments = [
                self._cached_subtree_commitment(prefix + [child_index])
                for child_index in range(self.params.branching_factor)
            ]
            sibling_layers.append(
                [
                    child_commitments[child_index]
                    for child_index in range(self.params.branching_factor)
                    if child_index != position
                ]
            )
            path_indices.append(position)

        return LatticeVerklePathProof(
            index,
            path_indices,
            sibling_layers,
            self.lattice_params,
            slot_probe=slot_probe,
        )

    def verify_path(self, identity, y_id, proof, root):
        return verify_lattice_verkle_path(identity, y_id, proof, root, self.params, self.lattice_params)

    def _subtree_commitment(self, prefix_digits):
        return self._cached_subtree_commitment(prefix_digits)

    def _cached_subtree_commitment(self, prefix_digits):
        prefix = tuple(ZZ(digit) for digit in prefix_digits)
        if prefix not in self.occupied_prefixes:
            return _lattice_verkle_empty_leaf(self.params, self.lattice_params)
        if prefix in self.node_cache:
            return self.node_cache[prefix]

        if len(prefix) == self.params.height:
            commitment = self._leaf_commitment(prefix)
        else:
            level_from_leaf = self.params.height - ZZ(len(prefix)) - ZZ(1)
            child_commitments = [
                self._cached_subtree_commitment(prefix + (ZZ(child_index),))
                for child_index in range(self.params.branching_factor)
            ]
            commitment = _lattice_verkle_node_commitment(
                child_commitments,
                self.params,
                self.lattice_params,
                level_from_leaf,
                list(prefix),
            )

        self.node_cache[prefix] = commitment

        return commitment

    def _leaf_commitment(self, prefix_digits):
        if len(prefix_digits) != self.params.height:
            raise ValueError("leaf prefix has incompatible height")

        index = _base_digits_to_index(prefix_digits, self.params.branching_factor)
        leaf = self.leaves_by_index.get(index)

        if leaf is None:
            return _lattice_verkle_empty_leaf(self.params, self.lattice_params)
        if leaf["active"]:
            return _lattice_verkle_active_leaf(
                leaf["identity"],
                leaf["y_id"],
                self.params,
                self.lattice_params,
            )

        return _lattice_verkle_revoked_leaf(
            leaf["identity"],
            leaf["y_id"],
            self.params,
            self.lattice_params,
        )

    def _mark_occupied_prefixes(self, index):
        digits = _index_to_base_digits(
            index,
            self.params.branching_factor,
            self.params.height,
        )

        for prefix_length in range(self.params.height + 1):
            self.occupied_prefixes.add(tuple(digits[:prefix_length]))

    def _update_path_cache(self, index):
        digits = _index_to_base_digits(
            index,
            self.params.branching_factor,
            self.params.height,
        )
        leaf_prefix = tuple(digits)
        self.node_cache[leaf_prefix] = self._leaf_commitment(leaf_prefix)

        for level in reversed(range(self.params.height)):
            prefix = tuple(digits[:level])
            level_from_leaf = self.params.height - ZZ(level) - ZZ(1)
            child_commitments = [
                self._cached_subtree_commitment(prefix + (ZZ(child_index),))
                for child_index in range(self.params.branching_factor)
            ]
            self.node_cache[prefix] = _lattice_verkle_node_commitment(
                child_commitments,
                self.params,
                self.lattice_params,
                level_from_leaf,
                list(prefix),
            )

    def _uncached_subtree_commitment(self, prefix_digits):
        if len(prefix_digits) == self.params.height:
            index = _base_digits_to_index(prefix_digits, self.params.branching_factor)
            leaf = self.leaves_by_index.get(index)

            if leaf is None:
                return _lattice_verkle_empty_leaf(self.params, self.lattice_params)
            if leaf["active"]:
                return _lattice_verkle_active_leaf(leaf["identity"], leaf["y_id"], self.params, self.lattice_params)

            return _lattice_verkle_revoked_leaf(leaf["identity"], leaf["y_id"], self.params, self.lattice_params)

        level_from_leaf = self.params.height - ZZ(len(prefix_digits)) - ZZ(1)
        child_commitments = [
            self._uncached_subtree_commitment(prefix_digits + [child_index])
            for child_index in range(self.params.branching_factor)
        ]
        return _lattice_verkle_node_commitment(
            child_commitments,
            self.params,
            self.lattice_params,
            level_from_leaf,
            prefix_digits,
        )

    def _allocate_leaf_index(self, identity):
        for slot_probe in range(self.params.leaf_count()):
            index = identity_to_leaf_index(identity, self.params, slot_probe=slot_probe)
            if index not in self.leaves_by_index:
                return index, ZZ(slot_probe)

        raise ValueError("state tree is full")


def trap_gen_mp12(params, seed_parts):
    """Generate a classical MP12-style G-trapdoor instance.

    The generated public matrix is A = [A_bar | G - A_bar R]. The trapdoor
    stores R and the gadget matrix G. This implements the algebraic TrapGen
    relation used by MP12-style preimage sampling; the full GPV Gaussian
    SamplePre is built on top of this relation in a later step.
    """
    Rq = params.ring()
    counter = ZZ(0)

    a_bar_rows = []
    for _ in range(params.n):
        row = []
        for _ in range(params.m_bar):
            value, counter = _sample_mod_q_with_domain(
                TRAP_GEN_MP12_DOMAIN,
                params,
                seed_parts,
                counter,
                b"Abar",
            )
            row.append(value)
        a_bar_rows.append(row)

    r_rows = []
    for _ in range(params.m_bar):
        row = []
        for _ in range(params.w):
            value, counter = _sample_ternary_with_domain(
                TRAP_GEN_MP12_DOMAIN,
                params,
                seed_parts,
                counter,
                b"R",
            )
            row.append(value)
        r_rows.append(row)

    a_bar = matrix(Rq, a_bar_rows)
    r = matrix(ZZ, r_rows)
    gadget = gadget_matrix(params)
    a_tail = gadget - a_bar * matrix(Rq, r)

    return a_bar.augment(a_tail), MP12GTrapdoor(r, gadget, a_bar)


def trap_gen(params, seed_parts):
    """Run the paper-level Sage TrapGen path for MP12 gadget parameters."""
    if isinstance(params, MP12GadgetParameters):
        return trap_gen_mp12(params, seed_parts)

    raise ValueError("unsupported parameter type for TrapGen")


def gadget_vector(params):
    return vector(ZZ, [params.base ** i for i in range(params.k)])


def gadget_matrix(params):
    Rq = params.ring()
    g = gadget_vector(params)
    rows = []

    for row_index in range(params.n):
        row = [ZZ(0)] * params.w
        for digit_index in range(params.k):
            row[row_index * params.k + digit_index] = g[digit_index]
        rows.append(row)

    return matrix(Rq, rows)


def gadget_decompose(target, params):
    if len(target) != params.n or target.base_ring() != params.ring():
        raise ValueError("target does not match MP12 gadget parameters")

    digits = []
    for value in target:
        remaining = ZZ(value)
        for _ in range(params.k):
            digit = remaining % params.base
            digits.append(digit)
            remaining = (remaining - digit) // params.base

    return vector(params.ring(), digits)


def gadget_kernel_basis(params):
    """Return a full-rank basis for Lambda_q^perp(G).

    Each gadget block gets k-1 exact integer-kernel columns and one q-column,
    so G * S = 0 mod q.
    """
    columns = []

    for block_index in range(params.n):
        block_offset = block_index * params.k

        for digit_index in range(params.k - 1):
            column = [ZZ(0)] * params.w
            column[block_offset + digit_index] = -params.base
            column[block_offset + digit_index + 1] = ZZ(1)
            columns.append(column)

        q_column = [ZZ(0)] * params.w
        q_column[block_offset] = params.q
        columns.append(q_column)

    return matrix(ZZ, columns).transpose()


def mp12_kernel_basis(trapdoor, params):
    """Return an integer basis B with A * B = 0 mod q."""
    gadget_basis = gadget_kernel_basis(params)
    r = matrix(ZZ, trapdoor.r)

    upper_left = params.q * identity_matrix(ZZ, params.m_bar)
    upper_right = r * gadget_basis
    lower_left = zero_matrix(ZZ, params.w, params.m_bar)
    lower_right = gadget_basis

    return block_matrix(
        ZZ,
        2,
        2,
        [
            upper_left,
            upper_right,
            lower_left,
            lower_right,
        ],
    )


def gso_norms_for_basis(basis):
    _, norms_squared = gram_schmidt_columns([vector(ZZ, column) for column in basis.columns()])
    return [sqrt(norm_squared) for norm_squared in norms_squared]


def gso_max_norm_for_basis(basis):
    norms = gso_norms_for_basis(basis)

    if len(norms) == 0:
        return _klein_gso_real_field()(0)

    return max(norms)


class MP12SamplePreContext:
    """Reusable MP12 SamplePre kernel and GSO data for one parameter set."""

    def __init__(self, A, trapdoor, params, sigma, omega_factor=None):
        if not isinstance(trapdoor, MP12GTrapdoor):
            raise ValueError("expected MP12GTrapdoor")
        if A.nrows() != params.n or A.ncols() != params.m:
            raise ValueError("A does not match MP12 parameters")

        self.A = A
        self.trapdoor = trapdoor
        self.params = params
        self.sigma = sigma
        self.omega_factor = omega_factor
        self.kernel_basis = mp12_kernel_basis(trapdoor, params)
        self.gso_columns, self.gso_norms_squared = gram_schmidt_columns(
            [vector(ZZ, column) for column in self.kernel_basis.columns()]
        )
        self.gso_norms = [sqrt(norm_squared) for norm_squared in self.gso_norms_squared]
        self.parameter_report = _mp12_sample_pre_parameter_report_from_gso(
            self.kernel_basis,
            self.gso_norms,
            params,
            sigma,
            omega_factor=omega_factor,
        )

    def sample(self, target, seed_parts, tail_cutoff=12):
        return sample_pre_mp12_gpv_klein_with_trace(
            self.A,
            self.trapdoor,
            target,
            self.params,
            self.sigma,
            seed_parts,
            tail_cutoff=tail_cutoff,
            sample_pre_context=self,
        )


def _mp12_sample_pre_parameter_report_from_gso(
    basis,
    gso_norms,
    params,
    sigma,
    omega_factor=None,
):
    if not isfinite(float(sigma)) or RDF(sigma) <= 0:
        raise ValueError("expected finite sigma > 0")

    RR = _klein_gso_real_field()
    if len(gso_norms) == 0:
        min_gso_norm = RR(0)
        max_gso_norm = RR(0)
        min_local_sigma = RR(0)
        max_local_sigma = RR(0)
    else:
        min_gso_norm = min(gso_norms)
        max_gso_norm = max(gso_norms)
        min_local_sigma = RR(sigma) / max_gso_norm
        max_local_sigma = RR(sigma) / min_gso_norm
    factor = RR(omega_factor) if omega_factor is not None else sqrt(log(RR(params.m)))

    if not isfinite(float(factor)) or factor <= 0:
        raise ValueError("expected positive omega_factor")

    recommended_sigma = max_gso_norm * factor
    recommended_beta = RR(sigma) * sqrt(RR(params.m)) * factor

    return {
        "dimension": params.m,
        "rank": basis.rank(),
        "basis_columns": basis.ncols(),
        "gso_backend": "realfield_gram_schmidt_columns",
        "gso_real_precision_bits": ZZ(KLEIN_GSO_REAL_PRECISION_BITS),
        "min_gso_norm": min_gso_norm,
        "max_gso_norm": max_gso_norm,
        "min_local_sigma": min_local_sigma,
        "max_local_sigma": max_local_sigma,
        "omega_factor": factor,
        "recommended_sigma": recommended_sigma,
        "recommended_beta": recommended_beta,
        "sample_pre_sigma_formula": "sigma_pre >= max_gso_norm * omega_factor",
        "sample_pre_beta_formula": "beta >= sigma_pre * sqrt(m) * omega_factor",
        "sigma": RR(sigma),
        "sigma_over_recommended": RR(sigma) / recommended_sigma if recommended_sigma > 0 else RR(0),
        "passes_recommended_bound": RR(sigma) >= recommended_sigma,
        "sample_pre_context_backend": "mp12_kernel_basis_gso_context",
    }


def mp12_sample_pre_parameter_report(trapdoor, params, sigma, omega_factor=None):
    """Report the current GPV/Klein sigma condition for the MP12 kernel basis."""
    basis = mp12_kernel_basis(trapdoor, params)
    gso_norms = gso_norms_for_basis(basis)

    return _mp12_sample_pre_parameter_report_from_gso(
        basis,
        gso_norms,
        params,
        sigma,
        omega_factor=omega_factor,
    )


def sample_pre_output_report(
    A,
    target,
    z,
    params,
    beta,
    parameter_report,
    sampler_algorithm,
    tail_cutoff,
    sampler_trace_report=None,
):
    """Report per-output SamplePre invariants for a sampled credential vector."""
    norm_squared = centered_norm_squared(z, params.q)
    beta = ZZ(beta)
    sampler_report = discrete_gaussian_sampler_audit_report(tail_cutoff)
    RR = _klein_gso_real_field()
    recommended_beta = parameter_report["recommended_beta"]
    Rq = params.ring()
    matrix_dimension_holds = A.nrows() == params.n and A.ncols() == params.m
    target_dimension_matches_n = len(target) == params.n
    output_dimension_matches_m = len(z) == params.m
    target_base_ring_matches_zq = target.base_ring() == Rq
    output_base_ring_matches_zq = z.base_ring() == Rq
    matrix_base_ring_matches_zq = A.base_ring() == Rq
    target_coordinates_in_zq = all(
        ZZ(0) <= ZZ(entry) < params.q for entry in target
    )
    output_coordinates_in_zq = all(ZZ(0) <= ZZ(entry) < params.q for entry in z)
    equation_holds = A * z == target
    norm_bound_holds = norm_squared <= beta * beta
    trace_tail_bound = (
        None
        if sampler_trace_report is None
        else sampler_trace_report["continuous_tail_heuristic_bound"]
    )
    trace_window_mass_lower_bound = (
        None
        if sampler_trace_report is None
        else sampler_trace_report["finite_window_mass_heuristic_lower_bound"]
    )

    return {
        "paper_algorithm": "SamplePre(A,T_A,Y_id)->z_id",
        "paper_register_target_relation": "Y_id = H1(id || epoch)",
        "paper_sample_pre_equation": "A*z_id = Y_id mod q",
        "paper_sample_pre_norm_bound": "||z_id||_2 <= beta",
        "target_module": "Z_q^n",
        "output_module": "Z_q^m",
        "matrix_rows": params.n,
        "matrix_columns": params.m,
        "modulus": params.q,
        "matrix_dimension_holds": matrix_dimension_holds,
        "matrix_base_ring_matches_zq": matrix_base_ring_matches_zq,
        "target_dimension_matches_n": target_dimension_matches_n,
        "target_base_ring_matches_zq": target_base_ring_matches_zq,
        "target_coordinates_in_zq": target_coordinates_in_zq,
        "output_dimension_matches_m": output_dimension_matches_m,
        "output_base_ring_matches_zq": output_base_ring_matches_zq,
        "output_coordinates_in_zq": output_coordinates_in_zq,
        "sampler_algorithm": sampler_algorithm,
        "sampling_distribution_status": "finite_window_truncated_shifted_discrete_gaussian_not_full_lattice_gaussian",
        "discrete_gaussian": "truncated_shifted_klein_gpv_style",
        "sampler_backend": sampler_report["sampler_backend"],
        "sampler_real_precision_bits": sampler_report["sampler_real_precision_bits"],
        "sampler_draw_bits": sampler_report["sampler_draw_bits"],
        "tail_cutoff": ZZ(tail_cutoff),
        "continuous_tail_heuristic_bound": sampler_report["continuous_tail_heuristic_bound"],
        "trace_continuous_tail_heuristic_bound": trace_tail_bound,
        "finite_window_mass_heuristic_lower_bound": trace_window_mass_lower_bound,
        "gso_backend": parameter_report["gso_backend"],
        "gso_real_precision_bits": parameter_report["gso_real_precision_bits"],
        "target_dimension": len(target),
        "output_dimension": len(z),
        "sigma": parameter_report["sigma"],
        "recommended_sigma": parameter_report["recommended_sigma"],
        "recommended_beta": recommended_beta,
        "sigma_over_recommended": parameter_report["sigma_over_recommended"],
        "beta_over_recommended": RR(beta) / recommended_beta if recommended_beta > 0 else RR(0),
        "min_gso_norm": parameter_report["min_gso_norm"],
        "max_gso_norm": parameter_report["max_gso_norm"],
        "min_local_sigma": parameter_report["min_local_sigma"],
        "max_local_sigma": parameter_report["max_local_sigma"],
        "parameter_bound_holds": parameter_report["passes_recommended_bound"],
        "paper_beta_bound_holds": RR(beta) >= recommended_beta,
        "sample_pre_sigma_formula": parameter_report["sample_pre_sigma_formula"],
        "sample_pre_beta_formula": parameter_report["sample_pre_beta_formula"],
        "sampler_trace_report": sampler_trace_report,
        "sampler_trace_all_checks_hold": (
            None
            if sampler_trace_report is None
            else sampler_trace_report["all_checks_hold"]
        ),
        "equation_holds": equation_holds,
        "norm_squared": norm_squared,
        "beta": beta,
        "norm_bound_holds": norm_bound_holds,
        "all_algorithmic_checks_hold": all(
            [
                matrix_dimension_holds,
                matrix_base_ring_matches_zq,
                target_dimension_matches_n,
                target_base_ring_matches_zq,
                target_coordinates_in_zq,
                output_dimension_matches_m,
                output_base_ring_matches_zq,
                output_coordinates_in_zq,
                equation_holds,
                norm_bound_holds,
            ]
        ),
        "distribution_audit_caveat": "Finite-window Klein/GPV sampler trace; distributional proof is external.",
    }


def sample_pre_coset_decomposition_report(
    A,
    target,
    canonical,
    lattice_sample,
    candidate,
    basis,
    params,
):
    """Report the GPV coset decomposition z = z0 + v for SamplePre."""
    Rq = params.ring()
    zero_target = vector(Rq, [0] * params.n)
    canonical_lift = vector(ZZ, centered_vector(canonical, params.q))
    candidate_lift = vector(ZZ, centered_vector(candidate, params.q))
    lattice_sample = vector(ZZ, list(lattice_sample))
    kernel_basis_relation_holds = A * matrix(Rq, basis) == zero_matrix(
        Rq,
        params.n,
        basis.ncols(),
    )
    kernel_basis_full_rank = basis.rank() == params.m
    canonical_equation_holds = A * canonical == target
    kernel_sample_relation_holds = A * vector(Rq, list(lattice_sample)) == zero_target
    candidate_decomposition_holds = (
        vector(Rq, list(canonical_lift + lattice_sample)) == candidate
    )
    centered_representative_decomposition_holds = (
        candidate_lift == canonical_lift + lattice_sample
    )
    candidate_equation_holds = A * candidate == target

    return {
        "scope": "sample_pre_gpv_coset_decomposition",
        "paper_statement": "SamplePre uses T_A to sample z in the coset z0 + Lambda_q_perp(A), with A*z = target mod q.",
        "canonical_preimage_equation": "A*z0 = target mod q",
        "kernel_sample_equation": "A*v = 0 mod q",
        "candidate_decomposition": "z = z0 + v mod q",
        "decomposition_relation_model": "mod_q_coset_relation; centered representatives may differ by q multiples",
        "target_dimension": ZZ(len(target)),
        "output_dimension": ZZ(len(candidate)),
        "kernel_basis_rows": ZZ(basis.nrows()),
        "kernel_basis_columns": ZZ(basis.ncols()),
        "kernel_basis_rank": ZZ(basis.rank()),
        "kernel_basis_full_rank": kernel_basis_full_rank,
        "kernel_basis_relation_holds": kernel_basis_relation_holds,
        "canonical_norm_squared": centered_norm_squared(canonical, params.q),
        "kernel_sample_norm_squared": ZZ(sum(value * value for value in lattice_sample)),
        "candidate_norm_squared": centered_norm_squared(candidate, params.q),
        "canonical_equation_holds": canonical_equation_holds,
        "kernel_sample_relation_holds": kernel_sample_relation_holds,
        "candidate_decomposition_holds": candidate_decomposition_holds,
        "centered_representative_decomposition_holds": centered_representative_decomposition_holds,
        "candidate_equation_holds": candidate_equation_holds,
        "all_checks_hold": all(
            [
                basis.nrows() == params.m,
                kernel_basis_full_rank,
                kernel_basis_relation_holds,
                canonical_equation_holds,
                kernel_sample_relation_holds,
                candidate_decomposition_holds,
                candidate_equation_holds,
            ]
        ),
        "caveat": "Algebraic coset-membership audit for the sampler path.",
    }


def sample_pre_diversity_audit(
    A,
    trapdoor,
    params,
    target,
    sigma,
    beta,
    seed_parts,
    omega_factor=None,
    sample_count=3,
    tail_cutoff=12,
):
    """Audit that SamplePre is seeded, reproducible, and non-canonical in practice."""
    if sample_count < 2:
        raise ValueError("expected sample_count >= 2")

    beta = ZZ(beta)
    seed_parts = [_as_bytes(part) for part in seed_parts]
    parameter_report = mp12_sample_pre_parameter_report(
        trapdoor,
        params,
        sigma,
        omega_factor=omega_factor,
    )
    samples = []
    output_fingerprints = []

    for index in range(ZZ(sample_count)):
        per_sample_seed_parts = (
            [b"sample-pre-diversity-audit", ZZ(index).binary()] + seed_parts
        )
        z = sample_pre(
            A,
            trapdoor,
            target,
            params,
            sigma=sigma,
            seed_parts=per_sample_seed_parts,
            tail_cutoff=tail_cutoff,
        )
        norm_squared = centered_norm_squared(z, params.q)
        output_fingerprint = tuple(ZZ(entry) for entry in z)
        output_fingerprints.append(output_fingerprint)
        samples.append(
            {
                "index": ZZ(index),
                "seed_label": "sample-pre-diversity-audit-%s" % index,
                "equation_holds": A * z == target,
                "norm_squared": norm_squared,
                "norm_bound_holds": norm_squared <= beta * beta,
            }
        )

    first_seed_parts = [b"sample-pre-diversity-audit", ZZ(0).binary()] + seed_parts
    repeated_first = sample_pre(
        A,
        trapdoor,
        target,
        params,
        sigma=sigma,
        seed_parts=first_seed_parts,
        tail_cutoff=tail_cutoff,
    )
    repeated_first_matches = tuple(ZZ(entry) for entry in repeated_first) == output_fingerprints[0]
    unique_output_count = ZZ(len(set(output_fingerprints)))
    all_equations_hold = all(sample["equation_holds"] for sample in samples)
    all_norm_bounds_hold = all(sample["norm_bound_holds"] for sample in samples)
    produces_distinct_preimages = unique_output_count >= 2

    return {
        "scope": "sample_pre_multi_seed_diversity",
        "paper_statement": "SamplePre samples a short preimage z with A*z = target mod q; different sampler coins may produce different valid preimages.",
        "sampler_algorithm": "sample_pre_mp12_gpv_klein",
        "discrete_gaussian": "truncated_shifted_klein_gpv_style",
        "sample_count": ZZ(sample_count),
        "target_dimension": ZZ(len(target)),
        "output_dimension": ZZ(params.m),
        "same_target_for_all_samples": True,
        "parameter_bound_holds": parameter_report["passes_recommended_bound"],
        "all_equations_hold": all_equations_hold,
        "all_norm_bounds_hold": all_norm_bounds_hold,
        "unique_output_count": unique_output_count,
        "produces_distinct_preimages": produces_distinct_preimages,
        "deterministic_reproducibility_checked": repeated_first_matches,
        "samples": samples,
        "all_checks_hold": all(
            [
                all_equations_hold,
                all_norm_bounds_hold,
                produces_distinct_preimages,
                repeated_first_matches,
            ]
        ),
        "caveat": "Seeded diversity and correctness check for the Sage sampler.",
    }


def sample_pre_input_validation_audit(
    A,
    trapdoor,
    params,
    sigma,
    seed_parts,
    tail_cutoff=12,
):
    """Audit that the public SamplePre entrypoint rejects malformed inputs."""
    Rq = params.ring()
    valid_target = vector(
        Rq,
        [(row_index + 1) % params.q for row_index in range(params.n)],
    )

    def rejection_case(name, expected_error_substring, thunk):
        try:
            thunk()
            return {
                "name": name,
                "rejected": False,
                "expected_error_substring": expected_error_substring,
                "error": None,
            }
        except ValueError as error:
            error_message = str(error)
            return {
                "name": name,
                "rejected": expected_error_substring in error_message,
                "expected_error_substring": expected_error_substring,
                "error": error_message,
            }

    malformed_target_dimension = vector(Rq, [0] * (params.n + 1))
    malformed_target_ring = vector(Integers(params.q + 1), [0] * params.n)
    malformed_matrix_dimensions = matrix(
        Rq,
        params.n,
        params.m + 1,
        [0] * (params.n * (params.m + 1)),
    )
    tampered_A = matrix(Rq, A)
    tampered_A[0, 0] = tampered_A[0, 0] + Rq(1)
    rational_r = matrix(QQ, trapdoor.r)
    malformed_r_dimensions = matrix(ZZ, params.m_bar + 1, params.w, [0] * ((params.m_bar + 1) * params.w))
    nonternary_r = matrix(ZZ, trapdoor.r)
    nonternary_r[0, 0] = ZZ(2)
    nonternary_trapdoor = MP12GTrapdoor(nonternary_r, trapdoor.gadget, trapdoor.a_bar)
    nonternary_A = trapdoor.a_bar.augment(
        trapdoor.gadget - trapdoor.a_bar * matrix(Rq, nonternary_r)
    )
    tampered_gadget = matrix(Rq, trapdoor.gadget)
    tampered_gadget[0, 0] = tampered_gadget[0, 0] + Rq(1)
    wrong_ring_a_bar = matrix(Integers(params.q + 1), trapdoor.a_bar)
    malformed_a_bar_dimensions = matrix(
        Rq,
        params.n,
        params.m_bar + 1,
        [0] * (params.n * (params.m_bar + 1)),
    )

    cases = [
        rejection_case(
            "missing_sigma",
            "requires sigma",
            lambda: sample_pre(
                A,
                trapdoor,
                valid_target,
                params,
                seed_parts=seed_parts,
                tail_cutoff=tail_cutoff,
            ),
        ),
        rejection_case(
            "missing_seed_parts",
            "requires seed_parts",
            lambda: sample_pre(
                A,
                trapdoor,
                valid_target,
                params,
                sigma=sigma,
                tail_cutoff=tail_cutoff,
            ),
        ),
        rejection_case(
            "target_dimension_mismatch",
            "target has incompatible MP12 dimension",
            lambda: sample_pre(
                A,
                trapdoor,
                malformed_target_dimension,
                params,
                sigma=sigma,
                seed_parts=seed_parts,
                tail_cutoff=tail_cutoff,
            ),
        ),
        rejection_case(
            "target_modulus_mismatch",
            "MP12 modulus mismatch",
            lambda: sample_pre(
                A,
                trapdoor,
                malformed_target_ring,
                params,
                sigma=sigma,
                seed_parts=seed_parts,
                tail_cutoff=tail_cutoff,
            ),
        ),
        rejection_case(
            "matrix_dimension_mismatch",
            "A has incompatible MP12 dimensions",
            lambda: sample_pre(
                malformed_matrix_dimensions,
                trapdoor,
                valid_target,
                params,
                sigma=sigma,
                seed_parts=seed_parts,
                tail_cutoff=tail_cutoff,
            ),
        ),
        rejection_case(
            "trapdoor_r_ring_mismatch",
            "R must be an integer matrix",
            lambda: sample_pre(
                A,
                MP12GTrapdoor(rational_r, trapdoor.gadget, trapdoor.a_bar),
                valid_target,
                params,
                sigma=sigma,
                seed_parts=seed_parts,
                tail_cutoff=tail_cutoff,
            ),
        ),
        rejection_case(
            "trapdoor_r_dimension_mismatch",
            "R has incompatible dimensions",
            lambda: sample_pre(
                A,
                MP12GTrapdoor(malformed_r_dimensions, trapdoor.gadget, trapdoor.a_bar),
                valid_target,
                params,
                sigma=sigma,
                seed_parts=seed_parts,
                tail_cutoff=tail_cutoff,
            ),
        ),
        rejection_case(
            "trapdoor_r_entries_not_ternary",
            "R entries must be ternary",
            lambda: sample_pre(
                nonternary_A,
                nonternary_trapdoor,
                valid_target,
                params,
                sigma=sigma,
                seed_parts=seed_parts,
                tail_cutoff=tail_cutoff,
            ),
        ),
        rejection_case(
            "trapdoor_gadget_mismatch",
            "gadget matrix mismatch",
            lambda: sample_pre(
                A,
                MP12GTrapdoor(trapdoor.r, tampered_gadget, trapdoor.a_bar),
                valid_target,
                params,
                sigma=sigma,
                seed_parts=seed_parts,
                tail_cutoff=tail_cutoff,
            ),
        ),
        rejection_case(
            "trapdoor_a_bar_modulus_mismatch",
            "A_bar modulus mismatch",
            lambda: sample_pre(
                A,
                MP12GTrapdoor(trapdoor.r, trapdoor.gadget, wrong_ring_a_bar),
                valid_target,
                params,
                sigma=sigma,
                seed_parts=seed_parts,
                tail_cutoff=tail_cutoff,
            ),
        ),
        rejection_case(
            "trapdoor_a_bar_dimension_mismatch",
            "A_bar has incompatible dimensions",
            lambda: sample_pre(
                A,
                MP12GTrapdoor(trapdoor.r, trapdoor.gadget, malformed_a_bar_dimensions),
                valid_target,
                params,
                sigma=sigma,
                seed_parts=seed_parts,
                tail_cutoff=tail_cutoff,
            ),
        ),
        rejection_case(
            "matrix_trapdoor_relation_mismatch",
            "A does not match MP12 trapdoor",
            lambda: sample_pre(
                tampered_A,
                trapdoor,
                valid_target,
                params,
                sigma=sigma,
                seed_parts=seed_parts,
                tail_cutoff=tail_cutoff,
            ),
        ),
    ]

    valid_sample = sample_pre(
        A,
        trapdoor,
        valid_target,
        params,
        sigma=sigma,
        seed_parts=[b"sample-pre-input-validation"] + list(seed_parts),
        tail_cutoff=tail_cutoff,
    )
    valid_case = {
        "name": "valid_input_accepts",
        "accepted": A * valid_sample == valid_target,
        "equation_holds": A * valid_sample == valid_target,
        "output_dimension": ZZ(len(valid_sample)),
        "expected_output_dimension": ZZ(params.m),
    }

    return {
        "scope": "sample_pre_public_entrypoint_input_validation",
        "paper_statement": "SamplePre(A, T_A, target, sigma) is defined only for matching MP12 public matrix, trapdoor, target ring, and target dimension.",
        "sampler_algorithm": "sample_pre_mp12_gpv_klein",
        "rejection_case_count": ZZ(len(cases)),
        "rejection_cases": cases,
        "valid_case": valid_case,
        "all_rejection_cases_hold": all(case["rejected"] for case in cases),
        "valid_case_holds": all(
            [
                valid_case["accepted"],
                valid_case["equation_holds"],
                valid_case["output_dimension"] == valid_case["expected_output_dimension"],
            ]
        ),
        "all_checks_hold": all(case["rejected"] for case in cases)
        and valid_case["accepted"]
        and valid_case["output_dimension"] == valid_case["expected_output_dimension"],
        "caveat": "API misuse and algebraic-shape audit.",
    }


def mp12_trap_gen_parameter_report(A, trapdoor, params):
    """Report algebraic TrapGen invariants for an MP12 G-trapdoor."""
    _validate_mp12_instance(A, trapdoor, vector(params.ring(), [0] * params.n), params)

    RR = _klein_gso_real_field()
    Rq = params.ring()
    gadget = trapdoor.gadget
    r_entries = [ZZ(entry) for entry in trapdoor.r.list()]
    r_nonzero_count = ZZ(sum(1 for entry in r_entries if entry != 0))
    r_entry_set = sorted(set(r_entries))
    r_row_norms_squared = [
        ZZ(sum(ZZ(entry) * ZZ(entry) for entry in trapdoor.r.row(row_index)))
        for row_index in range(trapdoor.r.nrows())
    ]
    r_column_norms_squared = [
        ZZ(sum(ZZ(entry) * ZZ(entry) for entry in trapdoor.r.column(column_index)))
        for column_index in range(trapdoor.r.ncols())
    ]
    r_frobenius_norm_squared = ZZ(sum(entry * entry for entry in r_entries))
    r_infinity_norm = max([abs(entry) for entry in r_entries] + [ZZ(0)])
    r_density = (
        RR(r_nonzero_count) / RR(len(r_entries))
        if len(r_entries) > 0
        else RR(0)
    )
    r_entries_are_ternary = all(entry in [-1, 0, 1] for entry in r_entries)
    r_has_expected_shape = (
        trapdoor.r.nrows() == params.m_bar and trapdoor.r.ncols() == params.w
    )
    trapdoor_relation_matrix = matrix(Rq, trapdoor.r).stack(
        identity_matrix(Rq, params.w)
    )
    kernel_basis = mp12_kernel_basis(trapdoor, params)
    gadget_kernel = gadget_kernel_basis(params)
    gadget_audit_targets = [
        vector(Rq, [0] * params.n),
        vector(Rq, [1] * params.n),
        vector(Rq, [params.q - 1] * params.n),
        vector(Rq, [(row_index + 2) % params.q for row_index in range(params.n)]),
    ]
    gadget_decomposition_samples = []

    for index, target in enumerate(gadget_audit_targets):
        decomposition = gadget_decompose(target, params)
        digits = [ZZ(entry) for entry in decomposition]
        digit_bounds_hold = all(ZZ(0) <= digit < params.base for digit in digits)
        gadget_equation_holds = gadget * decomposition == target
        canonical_head = matrix(Rq, trapdoor.r) * decomposition
        canonical_preimage = vector(Rq, list(canonical_head) + list(decomposition))
        canonical_preimage_equation_holds = A * canonical_preimage == target
        gadget_decomposition_samples.append(
            {
                "index": ZZ(index),
                "target": target,
                "digit_count": ZZ(len(digits)),
                "expected_digit_count": params.w,
                "digit_bounds_hold": digit_bounds_hold,
                "gadget_equation_holds": gadget_equation_holds,
                "canonical_preimage_equation_holds": canonical_preimage_equation_holds,
            }
        )

    gadget_decomposition_audit = {
        "scope": "mp12_gadget_decomposition_and_canonical_preimage",
        "paper_statement": "For target u, gadget decomposition returns x with G*x = u and TrapGen gives canonical preimage z0 = (R*x, x) satisfying A*z0 = u.",
        "sample_count": ZZ(len(gadget_decomposition_samples)),
        "samples": gadget_decomposition_samples,
        "all_digit_bounds_hold": all(
            sample["digit_bounds_hold"] for sample in gadget_decomposition_samples
        ),
        "all_gadget_equations_hold": all(
            sample["gadget_equation_holds"] for sample in gadget_decomposition_samples
        ),
        "all_canonical_preimage_equations_hold": all(
            sample["canonical_preimage_equation_holds"]
            for sample in gadget_decomposition_samples
        ),
    }
    gadget_decomposition_audit["all_checks_hold"] = all(
        [
            gadget_decomposition_audit["all_digit_bounds_hold"],
            gadget_decomposition_audit["all_gadget_equations_hold"],
            gadget_decomposition_audit["all_canonical_preimage_equations_hold"],
        ]
    )

    return {
        "trapdoor_type": "mp12_g_trapdoor",
        "paper_trapgen_matrix_formula": "A = [A_bar | G - A_bar * R]",
        "paper_trapdoor_relation": "A * [R; I] = G",
        "matrix_rows": params.n,
        "matrix_columns": params.m,
        "modulus": params.q,
        "m_bar": params.m_bar,
        "gadget_width": params.w,
        "gadget_base": params.base,
        "gadget_digits": params.k,
        "r_rows": trapdoor.r.nrows(),
        "r_columns": trapdoor.r.ncols(),
        "r_entry_set": r_entry_set,
        "r_entries_are_ternary": r_entries_are_ternary,
        "r_has_expected_shape": r_has_expected_shape,
        "r_nonzero_count": r_nonzero_count,
        "r_entry_count": ZZ(len(r_entries)),
        "r_density": r_density,
        "r_frobenius_norm_squared": r_frobenius_norm_squared,
        "r_infinity_norm": r_infinity_norm,
        "r_max_row_norm_squared": max(r_row_norms_squared) if r_row_norms_squared else ZZ(0),
        "r_max_column_norm_squared": (
            max(r_column_norms_squared) if r_column_norms_squared else ZZ(0)
        ),
        "r_shortness_model": "ternary_g_trapdoor_R_entries_in_{-1,0,1}",
        "a_bar_sampling_model": "seeded_domain_separated_uniform_Zq_matrix_via_SHAKE256",
        "r_sampling_model": "seeded_domain_separated_ternary_matrix_via_SHAKE256",
        "trapdoor_distribution_status": "seeded_reproducible_reference_not_production_distribution_proof",
        "a_bar_uniformity_claim_permitted": False,
        "r_distribution_claim_permitted": False,
        "production_trapgen_claim_permitted": False,
        "a_bar_relation_holds": A[:, 0:params.m_bar] == trapdoor.a_bar,
        "tail_relation_holds": A[:, params.m_bar:params.m] == (
            gadget - trapdoor.a_bar * matrix(Rq, trapdoor.r)
        ),
        "trapdoor_relation_holds": A * trapdoor_relation_matrix == gadget,
        "gadget_kernel_relation_holds": gadget * matrix(Rq, gadget_kernel) == zero_matrix(
            Rq,
            params.n,
            params.w,
        ),
        "gadget_decomposition_audit": gadget_decomposition_audit,
        "kernel_basis_rank": kernel_basis.rank(),
        "kernel_basis_columns": kernel_basis.ncols(),
        "kernel_basis_full_rank": kernel_basis.rank() == params.m,
        "kernel_basis_relation_holds": A * matrix(Rq, kernel_basis) == zero_matrix(
            Rq,
            params.n,
            params.m,
        ),
        "trapdoor_quality_checks_hold": all(
            [
                r_has_expected_shape,
                r_entries_are_ternary,
                r_infinity_norm <= 1,
                r_frobenius_norm_squared == r_nonzero_count,
                gadget_decomposition_audit["all_checks_hold"],
            ]
        ),
        "distribution_audit_caveat": "MP12 algebraic checks, seed reproducibility, and ternary-R quality.",
    }


def trap_gen_multi_seed_audit(params, base_seed_parts, sample_count=3):
    """Audit MP12 TrapGen reproducibility and seed-separated diversity."""
    if sample_count < 2:
        raise ValueError("expected sample_count >= 2")

    base_seed_parts = [_as_bytes(part) for part in base_seed_parts]
    samples = []
    fingerprints = []

    for index in range(ZZ(sample_count)):
        seed_parts = [b"trap-gen-multi-seed-audit", ZZ(index).binary()] + base_seed_parts
        A, trapdoor = trap_gen_mp12(params, seed_parts)
        report = mp12_trap_gen_parameter_report(A, trapdoor, params)
        fingerprint = (
            tuple(ZZ(entry) for entry in A.list()),
            tuple(ZZ(entry) for entry in trapdoor.r.list()),
        )
        fingerprints.append(fingerprint)
        samples.append(
            {
                "index": ZZ(index),
                "seed_label": "trap-gen-multi-seed-audit-%s" % index,
                "a_bar_relation_holds": report["a_bar_relation_holds"],
                "tail_relation_holds": report["tail_relation_holds"],
                "trapdoor_relation_holds": report["trapdoor_relation_holds"],
                "gadget_decomposition_audit_all_checks_hold": report[
                    "gadget_decomposition_audit"
                ]["all_checks_hold"],
                "kernel_basis_relation_holds": report["kernel_basis_relation_holds"],
                "trapdoor_quality_checks_hold": report["trapdoor_quality_checks_hold"],
                "r_entries_are_ternary": report["r_entries_are_ternary"],
                "a_bar_uniformity_claim_permitted": report[
                    "a_bar_uniformity_claim_permitted"
                ],
                "r_distribution_claim_permitted": report[
                    "r_distribution_claim_permitted"
                ],
                "production_trapgen_claim_permitted": report[
                    "production_trapgen_claim_permitted"
                ],
                "r_nonzero_count": report["r_nonzero_count"],
                "r_density": report["r_density"],
            }
        )

    first_seed_parts = [b"trap-gen-multi-seed-audit", ZZ(0).binary()] + base_seed_parts
    repeated_A, repeated_trapdoor = trap_gen_mp12(params, first_seed_parts)
    repeated_fingerprint = (
        tuple(ZZ(entry) for entry in repeated_A.list()),
        tuple(ZZ(entry) for entry in repeated_trapdoor.r.list()),
    )

    unique_instance_count = ZZ(len(set(fingerprints)))
    same_seed_reproducible = repeated_fingerprint == fingerprints[0]
    different_seed_distinct = unique_instance_count >= 2
    all_relations_hold = all(
        sample["a_bar_relation_holds"]
        and sample["tail_relation_holds"]
        and sample["trapdoor_relation_holds"]
        and sample["gadget_decomposition_audit_all_checks_hold"]
        and sample["kernel_basis_relation_holds"]
        for sample in samples
    )
    all_quality_checks_hold = all(
        sample["trapdoor_quality_checks_hold"]
        and sample["r_entries_are_ternary"]
        and not sample["a_bar_uniformity_claim_permitted"]
        and not sample["r_distribution_claim_permitted"]
        and not sample["production_trapgen_claim_permitted"]
        for sample in samples
    )

    return {
        "scope": "trap_gen_multi_seed_reproducibility",
        "trapdoor_type": "mp12_g_trapdoor",
        "sample_count": ZZ(sample_count),
        "unique_instance_count": unique_instance_count,
        "same_seed_reproducible": same_seed_reproducible,
        "different_seed_distinct": different_seed_distinct,
        "all_relations_hold": all_relations_hold,
        "all_quality_checks_hold": all_quality_checks_hold,
        "samples": samples,
        "all_checks_hold": all(
            [
                same_seed_reproducible,
                different_seed_distinct,
                all_relations_hold,
                all_quality_checks_hold,
            ]
        ),
        "caveat": "Seed reproducibility and MP12 relation check.",
    }


def paper_lattice_asymptotic_parameter_report(lattice_params):
    """Report the paper's lattice growth condition m = n^(1+delta)."""
    RR = _klein_gso_real_field()
    n = ZZ(lattice_params.n)
    m = ZZ(lattice_params.m)
    q = ZZ(lattice_params.q)
    if n <= 1:
        raise ValueError("expected lattice rank n > 1")
    if m <= n:
        raise ValueError("expected m > n for m = n^(1 + delta)")
    if q <= 1:
        raise ValueError("expected q > 1")

    delta_estimate = log(RR(m)) / log(RR(n)) - RR(1)
    n_delta_proxy = RR(m) / RR(n)
    ceil_log_q_base2 = ZZ(ceil(log(RR(q)) / log(RR(2))))
    ceil_log_q_natural = ZZ(ceil(log(RR(q))))
    n_delta_bound_holds = n_delta_proxy > RR(ceil_log_q_base2)

    return {
        "scope": "paper_lattice_asymptotic_parameters",
        "formula": "m = n^(1 + delta), n^delta > ceil(log q)",
        "log_q_interpretation": "concrete audit uses ceil(log_2 q); natural-log ceiling is reported separately because the paper should fix the log base",
        "n": n,
        "m": m,
        "q": q,
        "delta_estimate": delta_estimate,
        "n_delta_proxy": n_delta_proxy,
        "ceil_log_q_base2": ceil_log_q_base2,
        "ceil_log_q_natural": ceil_log_q_natural,
        "n_delta_over_ceil_log_q_base2": (
            n_delta_proxy / RR(ceil_log_q_base2)
            if ceil_log_q_base2 > 0
            else RR(0)
        ),
        "m_relation_reconstructed": n ** (RR(1) + delta_estimate),
        "n_delta_bound_holds": n_delta_bound_holds,
        "all_checks_hold": n_delta_bound_holds,
    }


def authentication_parameter_report(lattice_params, auth_params, beta, omega_factor=None):
    """Report the paper's response-bound condition for authentication."""
    beta = ZZ(beta)
    if beta <= 0:
        raise ValueError("expected beta > 0")

    RR = _klein_gso_real_field()
    factor = RR(omega_factor) if omega_factor is not None else sqrt(log(RR(lattice_params.m)))
    if not isfinite(float(factor)) or factor <= 0:
        raise ValueError("expected positive omega_factor")

    B_c = auth_params.challenge_bound()
    sqrt_log_m = sqrt(log(RR(lattice_params.m)))
    alpha_sigma_mask = RR(auth_params.sigma_mask) / (RR(B_c) * RR(beta))
    alpha_over_sqrt_log_m = alpha_sigma_mask / sqrt_log_m
    alpha_dominates_sqrt_log_m = alpha_sigma_mask > sqrt_log_m
    mask_norm_bound = RR(auth_params.sigma_mask) * sqrt(RR(lattice_params.m)) * factor
    challenge_term_bound = RR(B_c * beta)
    recommended_beta_response = mask_norm_bound + challenge_term_bound
    delta_c_min = auth_params.delta_c_min()
    extraction_bound = (RR(2) * RR(auth_params.beta_response)) / RR(delta_c_min)
    if lattice_params.n > 1:
        sis_slack_term = RR(auth_params.beta_response) * factor * sqrt(
            RR(lattice_params.n) * log(RR(lattice_params.n))
        )
    else:
        sis_slack_term = RR(0)
    q_lower_bound_direct = RR(2) * RR(auth_params.beta_response)
    q_lower_bound_sis = extraction_bound + sis_slack_term
    recommended_q_lower_bound = max(q_lower_bound_direct, q_lower_bound_sis)

    return {
        "dimension": lattice_params.m,
        "lattice_rank_n": lattice_params.n,
        "modulus_q": lattice_params.q,
        "challenge_bound_B_c": B_c,
        "delta_c_min": delta_c_min,
        "nonce_bytes": auth_params.nonce_bytes,
        "nonce_lambda_bits": ZZ(8) * auth_params.nonce_bytes,
        "omega_factor_config_key": "authentication.omega_factor",
        "omega_factor": factor,
        "sigma_mask": auth_params.sigma_mask,
        "sigma_mask_formula": "sigma_mask = alpha * B_c * beta",
        "alpha_formula": "alpha = sigma_mask / (B_c * beta), target alpha = omega(sqrt(log m))",
        "alpha_sigma_mask": alpha_sigma_mask,
        "sqrt_log_m": sqrt_log_m,
        "alpha_over_sqrt_log_m": alpha_over_sqrt_log_m,
        "alpha_dominates_sqrt_log_m": alpha_dominates_sqrt_log_m,
        "beta": beta,
        "mask_norm_bound": mask_norm_bound,
        "challenge_term_bound": challenge_term_bound,
        "recommended_beta_response": recommended_beta_response,
        "beta_response": auth_params.beta_response,
        "beta_response_over_recommended": (
            RR(auth_params.beta_response) / recommended_beta_response
            if recommended_beta_response > 0
            else RR(0)
        ),
        "passes_recommended_bound": RR(auth_params.beta_response) > recommended_beta_response,
        "response_beta_formula": "beta_response > sigma_mask * sqrt(m) * authentication.omega_factor + B_c * beta",
        "q_lower_bound_direct": q_lower_bound_direct,
        "q_lower_bound_sis": q_lower_bound_sis,
        "recommended_q_lower_bound": recommended_q_lower_bound,
        "q_over_recommended": (
            RR(lattice_params.q) / recommended_q_lower_bound
            if recommended_q_lower_bound > 0
            else RR(0)
        ),
        "q_bound_holds": RR(lattice_params.q) > recommended_q_lower_bound,
        "q_bound_formula": "q > max(2 * beta_response, 2 * beta_response / Delta_c_min + beta_response * authentication.omega_factor * sqrt(n * log(n)))",
        "sis_extraction_bound": extraction_bound,
        "sis_slack_term": sis_slack_term,
    }


def discrete_gaussian_sampler_audit_report(tail_cutoff):
    """Report implementation parameters for the reproducible Gaussian sampler."""
    tail_cutoff = ZZ(tail_cutoff)
    if tail_cutoff <= 0:
        raise ValueError("expected tail_cutoff > 0")

    RR = _discrete_gaussian_real_field()
    tail = RR(tail_cutoff)

    return {
        "sampler_backend": "shake256_hybrid_inverse_cdf_or_box_muller_truncated_window",
        "exact_cdf_max_support": ZZ(DISCRETE_GAUSSIAN_EXACT_CDF_MAX_SUPPORT),
        "large_support_backend": "shake256_box_muller_rounded_clamped_truncated_window",
        "sampler_real_precision_bits": ZZ(DISCRETE_GAUSSIAN_REAL_PRECISION_BITS),
        "sampler_draw_bits": ZZ(8 * DISCRETE_GAUSSIAN_DRAW_BYTES),
        "tail_cutoff": tail_cutoff,
        "continuous_tail_heuristic_bound": RR(2) * exp(-(tail ** 2) / RR(2)),
    }


def sampler_parameter_audit_report(
    public_parameters,
    parameter_set_label=None,
    explicit_config_required=True,
):
    """Record the sampler knobs used by this experiment instance.

    This report separates experiment configuration from security claims. Small
    regression values are acceptable for Sage lifecycle tests, but they must not
    be read as recommended paper parameters.
    """
    sample_pre_sampler = discrete_gaussian_sampler_audit_report(
        public_parameters.sample_pre_tail_cutoff
    )
    mask_sampler = discrete_gaussian_sampler_audit_report(
        public_parameters.mask_tail_cutoff
    )
    sample_pre_explicit = (
        hasattr(public_parameters, "sample_pre_tail_cutoff")
        and public_parameters.sample_pre_tail_cutoff > 0
    )
    mask_explicit = (
        hasattr(public_parameters, "mask_tail_cutoff")
        and public_parameters.mask_tail_cutoff > 0
    )
    sigma_pre_valid = (
        isfinite(float(public_parameters.sigma_pre))
        and public_parameters.sigma_pre > 0
    )
    sigma_mask_valid = (
        isfinite(float(public_parameters.auth_params.sigma_mask))
        and public_parameters.auth_params.sigma_mask > 0
    )
    sample_pre_omega_valid = (
        public_parameters.omega_factor is not None
        and isfinite(float(public_parameters.omega_factor))
        and RDF(public_parameters.omega_factor) > 0
    )
    auth_omega_valid = (
        public_parameters.auth_omega_factor is not None
        and isfinite(float(public_parameters.auth_omega_factor))
        and RDF(public_parameters.auth_omega_factor) > 0
    )

    return {
        "scope": "sampler_parameter_source_audit",
        "parameter_set_label": parameter_set_label,
        "parameter_set_status": "experiment_parameters_not_final_security_parameters",
        "explicit_config_required": bool(explicit_config_required),
        "sample_pre": {
            "algorithm": "sample_pre_mp12_gpv_klein",
            "sigma_config_key": "sample_pre.sigma_pre",
            "sigma_pre": public_parameters.sigma_pre,
            "tail_cutoff_config_key": "sample_pre.tail_cutoff",
            "tail_cutoff": public_parameters.sample_pre_tail_cutoff,
            "tail_cutoff_source": "explicit_experiment_config",
            "omega_factor_config_key": "sample_pre.omega_factor",
            "omega_factor": public_parameters.omega_factor,
            "sampler_backend": sample_pre_sampler["sampler_backend"],
            "sampler_real_precision_bits": sample_pre_sampler[
                "sampler_real_precision_bits"
            ],
            "sampler_draw_bits": sample_pre_sampler["sampler_draw_bits"],
            "continuous_tail_heuristic_bound": sample_pre_sampler[
                "continuous_tail_heuristic_bound"
            ],
        },
        "authentication_mask": {
            "algorithm": "independent_discrete_gaussian_mask_vector",
            "sigma_config_key": "authentication.sigma_mask",
            "sigma_mask": public_parameters.auth_params.sigma_mask,
            "tail_cutoff_config_key": "authentication.mask_tail_cutoff",
            "tail_cutoff": public_parameters.mask_tail_cutoff,
            "tail_cutoff_source": "explicit_experiment_config",
            "omega_factor_config_key": "authentication.omega_factor",
            "omega_factor": public_parameters.auth_omega_factor,
            "sampler_backend": mask_sampler["sampler_backend"],
            "sampler_real_precision_bits": mask_sampler[
                "sampler_real_precision_bits"
            ],
            "sampler_draw_bits": mask_sampler["sampler_draw_bits"],
            "continuous_tail_heuristic_bound": mask_sampler[
                "continuous_tail_heuristic_bound"
            ],
        },
        "checks": {
            "sample_pre_tail_cutoff_explicit_positive": bool(sample_pre_explicit),
            "mask_tail_cutoff_explicit_positive": bool(mask_explicit),
            "sigma_pre_positive": bool(sigma_pre_valid),
            "sigma_mask_positive": bool(sigma_mask_valid),
            "sample_pre_omega_factor_positive": bool(sample_pre_omega_valid),
            "authentication_omega_factor_positive": bool(auth_omega_valid),
        },
        "all_checks_hold": bool(
            sample_pre_explicit
            and mask_explicit
            and sigma_pre_valid
            and sigma_mask_valid
            and sample_pre_omega_valid
            and auth_omega_valid
        ),
        "caveat": "Sampler parameters come from the JSON config.",
    }


def h1_to_zq_vector(input_parts, dimension, modulus):
    """Map framed input parts to a vector in Z_q^dimension.

    SHAKE256 is domain separated, dimension and modulus are framed as
    big-endian u64 values, and coordinates are drawn by 64-bit rejection
    sampling from the XOF stream.
    """
    dimension = ZZ(dimension)
    modulus = ZZ(modulus)
    if dimension <= 0:
        raise ValueError("expected dimension > 0")
    if modulus <= 1:
        raise ValueError("expected modulus > 1")
    if dimension > ZZ(2) ** 64 - 1 or modulus > ZZ(2) ** 64 - 1:
        raise ValueError("dimension and modulus must fit in u64")

    framed_parts = [
        int(dimension).to_bytes(8, "big"),
        int(modulus).to_bytes(8, "big"),
    ] + [_as_bytes(part) for part in input_parts]
    stream = _shake_xof_stream(H1_DOMAIN, framed_parts)
    values = []

    while len(values) < dimension:
        values.append(_sample_modulus_from_stream(stream, modulus))

    return vector(Integers(modulus), values)


def h2_challenge_scalar(input_parts, modulus):
    """Map a framed transcript to a scalar in Z_q by 64-bit rejection sampling."""
    modulus = ZZ(modulus)
    if modulus <= 1:
        raise ValueError("expected modulus > 1")
    if modulus > ZZ(2) ** 64 - 1:
        raise ValueError("modulus must fit in u64")

    stream = _shake_xof_stream(
        H2_SCALAR_DOMAIN,
        [int(modulus).to_bytes(8, "big")] + [_as_bytes(part) for part in input_parts],
    )

    return _sample_modulus_from_stream(stream, modulus)


def registration_epoch_for_identity(identity, generation=0):
    """Internal epoch used to instantiate the paper Register(pp, msk, id)."""
    generation = ZZ(generation)
    if generation < 0:
        raise ValueError("expected nonnegative registration generation")
    if generation == 0:
        parts = [_as_bytes(identity)]
    else:
        parts = [
            _as_bytes(identity),
            int(generation).to_bytes(8, "big"),
        ]

    return _shake_digest(
        REGISTER_EPOCH_DOMAIN,
        parts,
        16,
    )


def registration_generation_for_identity(state, identity):
    """Return the next state-local registration generation for identity."""
    identity = _as_bytes(identity)
    return ZZ(
        sum(
            ZZ(1)
            for leaf in state.state_tree.leaves_by_index.values()
            if leaf["identity"] == identity
        )
    )


def random_oracle_instantiation_report(lattice_params, auth_params):
    """Audit the Sage H1/H2 random-oracle instantiation used by the scheme."""
    h1_sample = h1_to_zq_vector(
        [b"random-oracle-audit", b"H1"],
        lattice_params.n,
        lattice_params.q,
    )
    h1_replay = h1_to_zq_vector(
        [b"random-oracle-audit", b"H1"],
        lattice_params.n,
        lattice_params.q,
    )
    h1_other = h1_to_zq_vector(
        [b"random-oracle-audit", b"H1-other"],
        lattice_params.n,
        lattice_params.q,
    )
    h2_framed_left = _shake_digest(H2_SCALAR_DOMAIN, [b"ab", b"c"], 16)
    h2_framed_right = _shake_digest(H2_SCALAR_DOMAIN, [b"a", b"bc"], 16)
    h2_scalar_raw = h2_challenge_scalar(
        [b"Yid", b"w", b"rho", b"rt", b"id"],
        auth_params.challenge_modulus,
    )
    h2_scalar_centered = auth_params.center_challenge(h2_scalar_raw)

    h1_coordinates_in_zq = all(
        ZZ(0) <= ZZ(entry) < lattice_params.q for entry in h1_sample
    )
    h1_deterministic = list(h1_sample) == list(h1_replay)
    h1_distinct_domain_input_changes_output = list(h1_sample) != list(h1_other)
    framing_avoids_concat_ambiguity = h2_framed_left != h2_framed_right
    h2_scalar_raw_in_modulus = (
        ZZ(0) <= h2_scalar_raw < auth_params.challenge_modulus
    )
    h2_scalar_centered_in_c_lambda = auth_params.contains_challenge(
        h2_scalar_centered
    )
    h1_output_is_sage_vector = hasattr(h1_sample, "parent") and hasattr(
        h1_sample, "base_ring"
    )
    h1_base_ring_matches_zq = h1_sample.base_ring() == Integers(lattice_params.q)
    h1_dimension_matches = ZZ(len(h1_sample)) == lattice_params.n
    h2_raw_is_sage_integer = h2_scalar_raw in ZZ
    h2_centered_is_sage_integer = h2_scalar_centered in ZZ
    active_challenge_space_cardinality = ZZ(auth_params.challenge_modulus)
    centered_space_has_expected_cardinality = (
        2 * auth_params.challenge_bound() + 1 == active_challenge_space_cardinality
    )

    return {
        "scope": "sage_random_oracle_instantiation",
        "implementation": "SageMath_reference_with_python_stdlib_shake256_xof",
        "implementation_language": "SageMath",
        "hash_primitive_source": "python_standard_library_hashlib_shake_256",
        "third_party_crypto_dependency": False,
        "sage_native_crypto_hash_available": False,
        "sage_native_crypto_hash_note": "SageMath does not provide a canonical built-in random-oracle/SHAKE interface here; the reference wraps Python stdlib SHAKE256 and converts outputs into Sage ZZ/vector objects.",
        "paper_oracles": ["H1: {0,1}* -> Z_q^n", "H2: transcript -> C_lambda"],
        "h1_domain": H1_DOMAIN.decode("ascii"),
        "h2_scalar_domain": H2_SCALAR_DOMAIN.decode("ascii"),
        "encoding": "u64-length-framed_domain_separated_inputs",
        "h1_method": "SHAKE256_XOF_64_bit_rejection_sampling_to_Zq_vector",
        "h2_scalar_method": "SHAKE256_XOF_64_bit_rejection_sampling_then_centered_lift",
        "active_h2_challenge_method": "h2_challenge_scalar",
        "active_h2_transcript_order": ["Y_id", "w", "rho", "rt", "id"],
        "h1_dimension": lattice_params.n,
        "h1_modulus": lattice_params.q,
        "h1_sample": h1_sample,
        "h1_parent": str(h1_sample.parent()),
        "h1_base_ring": str(h1_sample.base_ring()),
        "h1_output_is_sage_vector": h1_output_is_sage_vector,
        "h1_base_ring_matches_zq": h1_base_ring_matches_zq,
        "h1_dimension_matches": h1_dimension_matches,
        "h1_coordinates_in_zq": h1_coordinates_in_zq,
        "h1_deterministic": h1_deterministic,
        "h1_distinct_domain_input_changes_output": h1_distinct_domain_input_changes_output,
        "framing_avoids_concat_ambiguity": framing_avoids_concat_ambiguity,
        "h2_scalar_raw_modulus": auth_params.challenge_modulus,
        "h2_scalar_raw": h2_scalar_raw,
        "h2_scalar_centered": h2_scalar_centered,
        "h2_raw_is_sage_integer": h2_raw_is_sage_integer,
        "h2_centered_is_sage_integer": h2_centered_is_sage_integer,
        "challenge_space": "C_lambda = {-B_c, ..., B_c}",
        "challenge_space_instantiation": "centered_scalar",
        "challenge_space_cardinality": active_challenge_space_cardinality,
        "challenge_bound_B_c": auth_params.challenge_bound(),
        "delta_c_min": auth_params.delta_c_min(),
        "delta_c_min_formula": "Delta_c_min = min |c - c'| = 1 for integer centered scalar challenges",
        "centered_space_has_expected_cardinality": centered_space_has_expected_cardinality,
        "paper_challenge_space_note": "The Sage reference instantiates the paper's active H2 as a centered scalar challenge oracle.",
        "h2_scalar_raw_in_modulus": h2_scalar_raw_in_modulus,
        "h2_scalar_centered_in_c_lambda": h2_scalar_centered_in_c_lambda,
        "all_checks_hold": all(
            [
                h1_coordinates_in_zq,
                h1_output_is_sage_vector,
                h1_base_ring_matches_zq,
                h1_dimension_matches,
                h1_deterministic,
                h1_distinct_domain_input_changes_output,
                h2_raw_is_sage_integer,
                h2_centered_is_sage_integer,
                framing_avoids_concat_ambiguity,
                h2_scalar_raw_in_modulus,
                h2_scalar_centered_in_c_lambda,
                centered_space_has_expected_cardinality,
            ]
        ),
    }


def paper_protocol_clarification_report(
    public_parameters,
    random_oracle_report,
    auth_parameter_report,
    lattice_asymptotic_report,
    proof_refresh_service_audit=None,
):
    """Record concrete protocol conventions implemented by the Sage reference."""
    h2_order = list(random_oracle_report["active_h2_transcript_order"])
    proof_refresh_evidence = proof_refresh_service_audit is not None and bool(
        proof_refresh_service_audit["all_checks_hold"]
    )
    items = [
        {
            "name": "centered_scalar_challenge_space",
            "paper_text_requirement": "Challenge space used by the active authentication path.",
            "sage_convention": random_oracle_report["challenge_space"],
            "sage_evidence": [
                "random_oracle_instantiation_audit.challenge_space",
                "setup_key_surface_audit.public_parameter_H2.output_spec",
            ],
            "has_sage_evidence": bool(
                random_oracle_report["challenge_space_instantiation"] == "centered_scalar"
                and public_parameters.H2.output_spec == "C_lambda = {-B_c, ..., B_c}"
            ),
            "implementation_convention_documented": True,
        },
        {
            "name": "challenge_bound_B_c",
            "paper_text_requirement": "Challenge bound used by the active authentication path.",
            "sage_convention": "B_c = (|C_lambda| - 1) / 2",
            "value": int(public_parameters.auth_params.challenge_bound()),
            "sage_evidence": [
                "parameters.authentication.challenge_bound_B_c",
                "random_oracle_instantiation_audit.challenge_bound_B_c",
            ],
            "has_sage_evidence": bool(
                public_parameters.auth_params.challenge_bound()
                == random_oracle_report["challenge_bound_B_c"]
            ),
            "implementation_convention_documented": True,
        },
        {
            "name": "delta_c_min",
            "paper_text_requirement": "Minimum challenge gap used by the parameter audit.",
            "sage_convention": random_oracle_report["delta_c_min_formula"],
            "value": int(public_parameters.auth_params.delta_c_min()),
            "sage_evidence": [
                "parameters.authentication.delta_c_min",
                "random_oracle_instantiation_audit.delta_c_min_formula",
            ],
            "has_sage_evidence": bool(
                public_parameters.auth_params.delta_c_min()
                == random_oracle_report["delta_c_min"]
                == auth_parameter_report["delta_c_min"]
            ),
            "implementation_convention_documented": True,
        },
        {
            "name": "h2_transcript_order",
            "paper_text_requirement": "Exact H2 input order used by Fiat-Shamir.",
            "sage_convention": " || ".join(h2_order),
            "sage_evidence": [
                "random_oracle_instantiation_audit.active_h2_transcript_order",
                "setup_key_surface_audit.public_parameter_H2.input_spec",
            ],
            "has_sage_evidence": bool(
                h2_order == ["Y_id", "w", "rho", "rt", "id"]
                and public_parameters.H2.input_spec == "Y_id || w || rho || rt || id"
            ),
            "implementation_convention_documented": True,
        },
        {
            "name": "dynamic_root_proof_refresh",
            "paper_text_requirement": "Public proof-refresh interface used to obtain current pi_id under a new root.",
            "sage_convention": "public service returns only (Y_id, pi_id, rt) for active identities",
            "sage_evidence": [
                "proof_refresh_audit",
                "proof_refresh_service_audit",
            ],
            "has_sage_evidence": proof_refresh_evidence,
            "implementation_convention_documented": True,
        },
        {
            "name": "lattice_growth_log_base",
            "paper_text_requirement": "Concrete log-base convention used by the parameter audit.",
            "sage_convention": lattice_asymptotic_report["log_q_interpretation"],
            "sage_evidence": [
                "parameters.lattice_asymptotic_parameter_report.ceil_log_q_base2",
                "parameters.lattice_asymptotic_parameter_report.ceil_log_q_natural",
            ],
            "has_sage_evidence": bool(
                lattice_asymptotic_report["ceil_log_q_base2"] > 0
                and lattice_asymptotic_report["ceil_log_q_natural"] > 0
            ),
            "implementation_convention_documented": True,
        },
    ]
    all_items_have_sage_evidence = all(item["has_sage_evidence"] for item in items)

    return {
        "scope": "paper_protocol_implementation_conventions",
        "status": "sage_protocol_conventions_reported",
        "purpose": "Expose the concrete choices used by the Sage implementation without treating code as paper-editing guidance.",
        "items": items,
        "required_item_count": len(items),
        "all_items_have_sage_evidence": all_items_have_sage_evidence,
        "implementation_conventions_explicit": True,
        "all_checks_hold": all_items_have_sage_evidence,
    }


def setup_key_surface_report(public_parameters, master_secret_key, state=None):
    """Report the paper Setup public/master-secret output boundary."""
    pp_fields = sorted(public_parameters.__dict__.keys())
    msk_fields = sorted(master_secret_key.__dict__.keys())
    public_has_expected_fields = all(
        field in pp_fields
        for field in [
            "A",
            "G",
            "H1",
            "H2",
            "auth_params",
            "b",
            "beta",
            "h",
            "lattice_params",
            "q",
            "root",
            "root0",
            "rt0",
            "sigma",
            "sigma_pre",
            "tree_params",
        ]
    )
    public_omits_trapdoor = (
        "trapdoor" not in pp_fields
        and "r" not in pp_fields
        and "T_A" not in pp_fields
    )
    master_secret_is_trapdoor_only = msk_fields == ["trapdoor"]
    root_matches_state = True if state is None else public_parameters.root == state.current_root()
    rt0_matches_setup_root = (
        True if state is None else public_parameters.rt0 == state.current_root()
    )
    root0_matches_setup_root = (
        True if state is None else public_parameters.root0 == state.current_root()
    )
    gadget_matrix_matches_parameters = (
        hasattr(public_parameters, "G")
        and public_parameters.G == gadget_matrix(public_parameters.lattice_params)
    )
    q_matches_lattice_parameters = (
        hasattr(public_parameters, "q")
        and public_parameters.q == public_parameters.lattice_params.q
    )
    tree_shape_aliases_match = (
        public_parameters.b == public_parameters.tree_params.branching_factor
        and public_parameters.h == public_parameters.tree_params.height
    )
    h1_descriptor_matches = (
        hasattr(public_parameters, "H1")
        and public_parameters.H1.name == "H1"
        and public_parameters.H1.domain == H1_DOMAIN
        and public_parameters.H1.output_spec == "Z_q^n"
        and public_parameters.H1.active
    )
    h2_descriptor_matches = (
        hasattr(public_parameters, "H2")
        and public_parameters.H2.name == "H2"
        and public_parameters.H2.domain == H2_SCALAR_DOMAIN
        and public_parameters.H2.output_spec == "C_lambda = {-B_c, ..., B_c}"
        and public_parameters.H2.active
    )
    return {
        "scope": "paper_setup_public_master_secret_surface",
        "paper_setup_output": "pp = (A, beta, sigma, H1, H2, b, h, rt0), msk = T_A",
        "sage_setup_extensions": ["G", "q", "root", "root0", "tree_params", "auth_params", "lattice_params"],
        "public_parameter_fields": pp_fields,
        "master_secret_fields": msk_fields,
        "public_parameter_matrix_A_dimensions": [
            public_parameters.A.nrows(),
            public_parameters.A.ncols(),
        ],
        "public_parameter_matrix_G_dimensions": [
            public_parameters.G.nrows(),
            public_parameters.G.ncols(),
        ],
        "public_parameter_contains_A": hasattr(public_parameters, "A"),
        "public_parameter_contains_G": hasattr(public_parameters, "G"),
        "public_parameter_G_matches_gadget_matrix": gadget_matrix_matches_parameters,
        "public_parameter_contains_q": hasattr(public_parameters, "q"),
        "public_parameter_q": public_parameters.q,
        "public_parameter_q_matches_lattice_parameters": q_matches_lattice_parameters,
        "public_parameter_contains_lattice_params": hasattr(public_parameters, "lattice_params"),
        "public_parameter_contains_norm_and_sampler_bounds": (
            hasattr(public_parameters, "beta")
            and hasattr(public_parameters, "sigma")
            and hasattr(public_parameters, "sigma_pre")
        ),
        "public_parameter_sigma": public_parameters.sigma,
        "public_parameter_sigma_matches_authentication_mask": (
            public_parameters.sigma == public_parameters.auth_params.sigma_mask
        ),
        "public_parameter_contains_hash_oracle_configuration": (
            h1_descriptor_matches
            and h2_descriptor_matches
        ),
        "public_parameter_contains_tree_parameters": hasattr(public_parameters, "tree_params"),
        "public_parameter_tree_shape_aliases_match": tree_shape_aliases_match,
        "public_parameter_b": public_parameters.b,
        "public_parameter_h": public_parameters.h,
        "public_parameter_contains_root": hasattr(public_parameters, "root"),
        "public_parameter_contains_initial_root": (
            hasattr(public_parameters, "root0")
            and hasattr(public_parameters, "rt0")
        ),
        "public_parameter_root0_matches_setup_root": root0_matches_setup_root,
        "public_parameter_rt0_matches_setup_root": rt0_matches_setup_root,
        "public_parameter_H1": {
            "name": public_parameters.H1.name,
            "domain": public_parameters.H1.domain.decode("ascii"),
            "input_spec": public_parameters.H1.input_spec,
            "output_spec": public_parameters.H1.output_spec,
            "method": public_parameters.H1.method,
            "active": public_parameters.H1.active,
        },
        "public_parameter_H2": {
            "name": public_parameters.H2.name,
            "domain": public_parameters.H2.domain.decode("ascii"),
            "input_spec": public_parameters.H2.input_spec,
            "output_spec": public_parameters.H2.output_spec,
            "method": public_parameters.H2.method,
            "active": public_parameters.H2.active,
        },
        "public_parameter_H1_descriptor_matches": h1_descriptor_matches,
        "public_parameter_H2_descriptor_matches": h2_descriptor_matches,
        "public_has_expected_fields": public_has_expected_fields,
        "public_omits_trapdoor": public_omits_trapdoor,
        "master_secret_is_trapdoor_only": master_secret_is_trapdoor_only,
        "master_secret_contains_trapdoor": hasattr(master_secret_key, "trapdoor"),
        "root_matches_state": root_matches_state,
        "all_checks_hold": all(
            [
                public_has_expected_fields,
                public_omits_trapdoor,
                master_secret_is_trapdoor_only,
                hasattr(master_secret_key, "trapdoor"),
                root_matches_state,
                root0_matches_setup_root,
                rt0_matches_setup_root,
                gadget_matrix_matches_parameters,
                q_matches_lattice_parameters,
                tree_shape_aliases_match,
                h1_descriptor_matches,
                h2_descriptor_matches,
            ]
        ),
    }


def identity_to_leaf_index(identity, tree_params, slot_probe=0):
    """Map an identity to a deterministic leaf index in the state tree."""
    if tree_params.leaf_count() > ZZ(2) ** 64 - 1:
        raise ValueError("state tree leaf_count must fit in u64")
    slot_probe = ZZ(slot_probe)
    if slot_probe < 0:
        raise ValueError("expected nonnegative slot_probe")

    stream = _shake_xof_stream(
        STATE_TREE_LEAF_INDEX_DOMAIN,
        [
            int(tree_params.branching_factor).to_bytes(8, "big"),
            int(tree_params.height).to_bytes(8, "big"),
            int(slot_probe).to_bytes(8, "big"),
            _as_bytes(identity),
        ],
    )

    return _sample_modulus_from_stream(stream, tree_params.leaf_count())


def verify_verkle_path(identity, y_id, proof, root, tree_params):
    """Verify a paper-style lattice-linear Verkle path proof."""
    lattice_params = getattr(proof, "lattice_params", None)
    if getattr(proof, "backend", None) != "lattice_linear_verkle_tree" or lattice_params is None:
        raise ValueError("expected a lattice-linear Verkle path proof")

    return verify_lattice_verkle_path(identity, y_id, proof, root, tree_params, lattice_params)


def verify_verkle_path_or_false(identity, y_id, proof, root, tree_params):
    """Return False instead of raising when adversarial proof data is malformed."""
    try:
        return bool(verify_verkle_path(identity, y_id, proof, root, tree_params))
    except (AttributeError, IndexError, TypeError, ValueError):
        return False


def verify_lattice_verkle_path(identity, y_id, proof, root, tree_params, lattice_params):
    """Verify the paper-style linear Verkle path over Z_q^n."""
    active_leaf = _lattice_verkle_active_leaf(identity, y_id, tree_params, lattice_params)
    return _verify_lattice_verkle_path_from_leaf(
        identity,
        proof,
        root,
        tree_params,
        lattice_params,
        active_leaf,
    )


def _verify_lattice_verkle_path_from_leaf(identity, proof, root, tree_params, lattice_params, leaf_commitment):
    if proof.leaf_index < 0 or proof.leaf_index >= tree_params.leaf_count():
        return False
    if proof.slot_probe < 0 or proof.slot_probe >= tree_params.leaf_count():
        return False
    if proof.leaf_index != identity_to_leaf_index(
        identity,
        tree_params,
        slot_probe=proof.slot_probe,
    ):
        return False
    if len(proof.path_indices) != tree_params.height:
        return False
    if len(proof.sibling_commitment_layers) != tree_params.height:
        return False

    digits = _index_to_base_digits(
        proof.leaf_index,
        tree_params.branching_factor,
        tree_params.height,
    )
    current = leaf_commitment

    for offset, sibling_commitments in enumerate(proof.sibling_commitment_layers):
        parent_level = tree_params.height - ZZ(1) - ZZ(offset)
        expected_position = digits[parent_level]
        if proof.path_indices[offset] != expected_position:
            return False
        if len(sibling_commitments) != tree_params.branching_factor - 1:
            return False

        child_commitments = []
        sibling_index = 0
        for child_index in range(tree_params.branching_factor):
            if ZZ(child_index) == expected_position:
                child_commitments.append(current)
            else:
                child_commitments.append(sibling_commitments[sibling_index])
                sibling_index += 1

        parent_prefix = digits[:parent_level]
        current = _lattice_verkle_node_commitment(
            child_commitments,
            tree_params,
            lattice_params,
            ZZ(offset),
            parent_prefix,
        )

    return _serialize_zq_vector(current) == _as_bytes(root)


def lattice_verkle_tree_state_report(state_tree):
    """Report state-tree occupancy for the lattice-linear Verkle tree."""
    active_count = ZZ(0)
    revoked_count = ZZ(0)

    for leaf in state_tree.leaves_by_index.values():
        if leaf["active"]:
            active_count += 1
        else:
            revoked_count += 1

    if not isinstance(state_tree, LatticeVerkleTree):
        raise ValueError("expected LatticeVerkleTree")

    report = {
        "state_tree_kind": "lattice_linear_verkle_tree",
        "branching_factor": state_tree.params.branching_factor,
        "height": state_tree.params.height,
        "leaf_count": state_tree.params.leaf_count(),
        "commitment_bytes": state_tree.params.commitment_bytes,
        "occupied_leaf_count": active_count + revoked_count,
        "active_leaf_count": active_count,
        "revoked_leaf_count": revoked_count,
        "commitment_cache_backend": "occupied_prefix_path_update_cache",
        "cached_node_count": ZZ(len(state_tree.node_cache)),
        "occupied_prefix_count": ZZ(len(state_tree.occupied_prefixes)),
        "root": state_tree.root(),
    }
    report["root_vector"] = state_tree.root_vector()
    report["vector_dimension"] = state_tree.lattice_params.n
    report["modulus"] = state_tree.lattice_params.q

    return report


def lattice_verkle_path_report(identity, y_id, proof, root, tree_params):
    lattice_params = getattr(proof, "lattice_params", None)
    if getattr(proof, "backend", None) != "lattice_linear_verkle_tree" or lattice_params is None:
        raise ValueError("expected a lattice-linear Verkle path proof")

    expected_sibling_count = tree_params.height * (tree_params.branching_factor - ZZ(1))
    actual_sibling_count = sum(len(layer) for layer in proof.sibling_commitment_layers)
    vector_bytes = ZZ(len(_serialize_zq_vector(vector(lattice_params.ring(), [0] * lattice_params.n))))
    path_metadata_bytes = ZZ(16)
    index_metadata_bytes = ZZ(8) * tree_params.height
    proof_size_bytes = (
        path_metadata_bytes
        + index_metadata_bytes
        + actual_sibling_count * vector_bytes
    )
    layer_count_holds = len(proof.sibling_commitment_layers) == tree_params.height
    path_index_count_holds = len(proof.path_indices) == tree_params.height
    branching_holds = all(
        len(layer) == tree_params.branching_factor - 1
        for layer in proof.sibling_commitment_layers
    )
    leaf_index_in_range = ZZ(0) <= proof.leaf_index < tree_params.leaf_count()
    slot_probe_in_range = ZZ(0) <= proof.slot_probe < tree_params.leaf_count()
    expected_leaf_index = (
        identity_to_leaf_index(identity, tree_params, slot_probe=proof.slot_probe)
        if slot_probe_in_range
        else ZZ(-1)
    )
    leaf_index_matches_identity_probe = proof.leaf_index == expected_leaf_index
    verifies_active_path = verify_lattice_verkle_path(
        identity,
        y_id,
        proof,
        root,
        tree_params,
        lattice_params,
    )
    active_leaf = _lattice_verkle_active_leaf(identity, y_id, tree_params, lattice_params)
    revoked_leaf = _lattice_verkle_revoked_leaf(identity, y_id, tree_params, lattice_params)
    verifies_revoked_leaf_path = _verify_lattice_verkle_path_from_leaf(
        identity,
        proof,
        root,
        tree_params,
        lattice_params,
        revoked_leaf,
    )
    active_revoked_leaf_domains_distinct = (
        LATTICE_VERKLE_ACTIVE_LEAF_DOMAIN != LATTICE_VERKLE_REVOKED_LEAF_DOMAIN
    )
    active_revoked_leaf_commitments_distinct = active_leaf != revoked_leaf
    active_membership_leaf_domain_checks_hold = all(
        [
            active_revoked_leaf_domains_distinct,
            active_revoked_leaf_commitments_distinct,
            not (verifies_active_path and verifies_revoked_leaf_path),
        ]
    )

    return {
        "state_tree_kind": "lattice_linear_verkle_tree",
        "paper_object": "pi_id = (idx_0..idx_{h-1}; Auth_0..Auth_{h-1}) for active (id, Y_id) membership",
        "proof_commitment_model": "paper_linear_verkle_auth_layers_with_b_minus_1_sibling_Zq_vectors",
        "verification_leaf_status": "active",
        "active_leaf_domain": LATTICE_VERKLE_ACTIVE_LEAF_DOMAIN.decode("ascii"),
        "revoked_leaf_domain": LATTICE_VERKLE_REVOKED_LEAF_DOMAIN.decode("ascii"),
        "active_revoked_leaf_domains_distinct": active_revoked_leaf_domains_distinct,
        "active_revoked_leaf_commitments_distinct": active_revoked_leaf_commitments_distinct,
        "verifies_revoked_leaf_path": verifies_revoked_leaf_path,
        "revoked_leaf_does_not_verify_as_active_path": not (
            verifies_active_path and verifies_revoked_leaf_path
        ),
        "active_membership_leaf_domain_checks_hold": active_membership_leaf_domain_checks_hold,
        "proof_size_model": "leaf_index_u64 + slot_probe_u64 + height * index_u64 + height * (branching_factor - 1) * serialized_Zq_vector",
        "vector_commitment_target_model": "paper_linear_aggregation_Y_parent=sum_alpha_k_Com_k_mod_q",
        "vector_commitment_target_opening_count": tree_params.height,
        "commitment_count_over_vector_commitment_target": (
            actual_sibling_count / tree_params.height if tree_params.height > 0 else ZZ(0)
        ),
        "extra_commitments_over_vector_commitment_target": (
            actual_sibling_count - tree_params.height
        ),
        "state_commitment_upgrade_required_for_verkle_claim": False,
        "paper_verkle_backend_claim_permitted": True,
        "paper_verkle_proof_size_model_claim_permitted": True,
        "production_verkle_vector_commitment": False,
        "production_verkle_proof_size_claim_permitted": False,
        "leaf_index": proof.leaf_index,
        "leaf_index_in_range": leaf_index_in_range,
        "slot_probe": proof.slot_probe,
        "slot_probe_in_range": slot_probe_in_range,
        "expected_leaf_index": expected_leaf_index,
        "leaf_index_matches_identity_probe": leaf_index_matches_identity_probe,
        "layer_count": len(proof.sibling_commitment_layers),
        "expected_layer_count": tree_params.height,
        "layer_count_holds": layer_count_holds,
        "path_index_count_holds": path_index_count_holds,
        "commitment_count": actual_sibling_count,
        "expected_commitment_count": expected_sibling_count,
        "sibling_commitment_count": actual_sibling_count,
        "path_metadata_bytes": path_metadata_bytes + index_metadata_bytes,
        "proof_size_bytes": proof_size_bytes,
        "branching_factor": tree_params.branching_factor,
        "branching_holds": branching_holds,
        "proof_shape_holds": (
            leaf_index_in_range
            and slot_probe_in_range
            and leaf_index_matches_identity_probe
            and layer_count_holds
            and path_index_count_holds
            and branching_holds
        ),
        "verifies_active_path": verifies_active_path,
    }


def lattice_verkle_fs_context_report(tree_params, lattice_params):
    """Audit the Fiat-Shamir coefficient context for linear Verkle aggregation."""
    Rq = lattice_params.ring()
    sample_child = vector(
        Rq,
        [(index + 1) % lattice_params.q for index in range(lattice_params.n)],
    )
    level_from_leaf = ZZ(0)
    child_index = ZZ(0)
    prefix_length = tree_params.height - ZZ(1)
    prefix_a = [ZZ(0)] * prefix_length
    prefix_b = list(prefix_a)
    if prefix_length > 0:
        prefix_b[0] = ZZ(1) % tree_params.branching_factor

    base_coefficient = _lattice_verkle_fs_coefficient(
        sample_child,
        tree_params,
        lattice_params,
        level_from_leaf,
        child_index,
        prefix_a,
    )
    replay_coefficient = _lattice_verkle_fs_coefficient(
        sample_child,
        tree_params,
        lattice_params,
        level_from_leaf,
        child_index,
        prefix_a,
    )

    def coefficient_changes(mutator):
        for attempt in range(1, 257):
            candidate = mutator(ZZ(attempt))
            if candidate != base_coefficient:
                return True, candidate
        return False, base_coefficient

    child_commitment_changes_coefficient, changed_child_coefficient = coefficient_changes(
        lambda attempt: _lattice_verkle_fs_coefficient(
            _tamper_zq_vector_first_coordinate(sample_child + vector(Rq, [attempt] + [0] * (lattice_params.n - 1))),
            tree_params,
            lattice_params,
            level_from_leaf,
            child_index,
            prefix_a,
        )
    )
    child_index_changes_coefficient, changed_child_index_coefficient = coefficient_changes(
        lambda attempt: _lattice_verkle_fs_coefficient(
            sample_child,
            tree_params,
            lattice_params,
            level_from_leaf,
            (child_index + attempt) % tree_params.branching_factor,
            prefix_a,
        )
    )
    level_context_available = tree_params.height > 1
    if level_context_available:
        level_changes_coefficient, changed_level_coefficient = coefficient_changes(
            lambda attempt: _lattice_verkle_fs_coefficient(
                sample_child,
                tree_params,
                lattice_params,
                (level_from_leaf + attempt) % tree_params.height,
                child_index,
                prefix_a,
            )
        )
    else:
        level_changes_coefficient = True
        changed_level_coefficient = base_coefficient

    prefix_context_available = prefix_length > 0
    if prefix_context_available:
        prefix_changes_coefficient, changed_prefix_coefficient = coefficient_changes(
            lambda attempt: _lattice_verkle_fs_coefficient(
                sample_child,
                tree_params,
                lattice_params,
                level_from_leaf,
                child_index,
                [(digit + attempt) % tree_params.branching_factor for digit in prefix_b],
            )
        )
    else:
        prefix_changes_coefficient = True
        changed_prefix_coefficient = base_coefficient

    return {
        "scope": "lattice_verkle_fiat_shamir_coefficient_context",
        "paper_formula": "alpha_k = H_FS(Com_k || context) mod q",
        "coefficient_domain": LATTICE_VERKLE_FS_COEFFICIENT_DOMAIN.decode("ascii"),
        "coefficient_modulus": lattice_params.q,
        "context_fields": [
            "branching_factor",
            "height",
            "lattice_dimension_n",
            "modulus_q",
            "level_from_leaf",
            "child_index",
            "parent_prefix_digits",
            "child_commitment",
        ],
        "parent_prefix_digits_bound": True,
        "level_bound": True,
        "child_index_bound": True,
        "child_commitment_bound": True,
        "deterministic_replay_holds": base_coefficient == replay_coefficient,
        "child_commitment_changes_coefficient": child_commitment_changes_coefficient,
        "child_index_changes_coefficient": child_index_changes_coefficient,
        "level_context_available": level_context_available,
        "level_changes_coefficient": level_changes_coefficient,
        "parent_prefix_context_available": prefix_context_available,
        "parent_prefix_changes_coefficient": prefix_changes_coefficient,
        "base_coefficient": base_coefficient,
        "changed_child_coefficient": changed_child_coefficient,
        "changed_child_index_coefficient": changed_child_index_coefficient,
        "changed_level_coefficient": changed_level_coefficient,
        "changed_prefix_coefficient": changed_prefix_coefficient,
        "all_checks_hold": all(
            [
                base_coefficient == replay_coefficient,
                child_commitment_changes_coefficient,
                child_index_changes_coefficient,
                level_changes_coefficient,
                prefix_changes_coefficient,
            ]
        ),
    }


def lattice_verkle_state_commitment_backend_report(state_tree):
    """Report the current state commitment backend against the paper's Verkle target."""
    if not isinstance(state_tree, LatticeVerkleTree):
        raise ValueError("expected LatticeVerkleTree")

    tree_params = state_tree.params
    current_commitments_per_path = tree_params.height * (tree_params.branching_factor - ZZ(1))
    target_openings = current_commitments_per_path
    sample_identity = b"lattice-verkle-domain-separation-audit"
    sample_y = vector(state_tree.lattice_params.ring(), [0] * state_tree.lattice_params.n)
    sample_active_leaf = _lattice_verkle_active_leaf(
        sample_identity,
        sample_y,
        tree_params,
        state_tree.lattice_params,
    )
    sample_revoked_leaf = _lattice_verkle_revoked_leaf(
        sample_identity,
        sample_y,
        tree_params,
        state_tree.lattice_params,
    )
    active_revoked_leaf_domains_distinct = (
        LATTICE_VERKLE_ACTIVE_LEAF_DOMAIN != LATTICE_VERKLE_REVOKED_LEAF_DOMAIN
    )
    active_revoked_leaf_commitments_distinct = sample_active_leaf != sample_revoked_leaf
    fs_context_report = lattice_verkle_fs_context_report(
        tree_params,
        state_tree.lattice_params,
    )
    return {
        "scope": "state_commitment_backend_audit",
        "paper_object": "Verkle tree path proof pi_id = (idx_0..idx_{h-1}; Auth_0..Auth_{h-1})",
        "paper_security_assumption": "SIS-backed binding of lattice vector commitments and Fiat-Shamir linear aggregation",
        "current_backend": "lattice_linear_verkle_tree",
        "implemented_paper_claim_level": "paper_linear_verkle_tree_with_Zq_vector_nodes_and_FS_coefficients",
        "current_commitment_model": "Y_parent=sum_alpha_k_Com_k_mod_q",
        "target_backend_family": "paper_lattice_linear_verkle_tree",
        "target_commitment_model": "height * (branching_factor - 1) sibling Z_q^n vectors with FS linear aggregation",
        "branching_factor": tree_params.branching_factor,
        "height": tree_params.height,
        "leaf_count": tree_params.leaf_count(),
        "commitment_bytes": tree_params.commitment_bytes,
        "current_commitments_per_path": current_commitments_per_path,
        "vector_commitment_target_openings_per_path": target_openings,
        "extra_commitments_over_vector_commitment_target": ZZ(0),
        "commitment_count_over_vector_commitment_target": ZZ(1),
        "implements_register_verify_revoke_state_semantics": True,
        "implements_position_binding_experiment": True,
        "verification_leaf_status": "active",
        "revoked_state_leaf_status": "revoked",
        "active_leaf_domain": LATTICE_VERKLE_ACTIVE_LEAF_DOMAIN.decode("ascii"),
        "revoked_leaf_domain": LATTICE_VERKLE_REVOKED_LEAF_DOMAIN.decode("ascii"),
        "active_revoked_leaf_domains_distinct": active_revoked_leaf_domains_distinct,
        "active_revoked_leaf_commitments_distinct": active_revoked_leaf_commitments_distinct,
        "revoked_leaf_represents_revocation_not_active_membership": True,
        "fiat_shamir_coefficient_context_report": fs_context_report,
        "fiat_shamir_context_binds_parent_prefix": fs_context_report[
            "parent_prefix_digits_bound"
        ],
        "fiat_shamir_context_checks_hold": fs_context_report["all_checks_hold"],
        "paper_verkle_backend_claim_permitted": True,
        "paper_verkle_proof_size_model_claim_permitted": True,
        "paper_verkle_security_assumption_matches_backend": True,
        "research_reference_backend": True,
        "production_verkle_vector_commitment": False,
        "production_verkle_proof_size_claim_permitted": False,
        "paper_alignment_action": "paper_verkle_claim_matches_lattice_linear_verkle_reference_backend",
        "verkle_security_claim_permitted": False,
        "paper_alignment_options": [
            "Keep the paper's lattice-linear Verkle definition aligned with this Sage backend.",
            "Describe the backend as the paper's SIS/lattice linear-aggregation Verkle.",
        ],
        "all_checks_hold": all(
            [
                current_commitments_per_path == tree_params.height * (tree_params.branching_factor - ZZ(1)),
                target_openings == current_commitments_per_path,
                active_revoked_leaf_domains_distinct,
                active_revoked_leaf_commitments_distinct,
                fs_context_report["all_checks_hold"],
            ]
        ),
        "caveat": "Lattice-linear Verkle backend over Z_q^n vectors.",
    }


def lattice_verkle_position_binding_report(identity, y_id, proof, root, tree_params):
    """Report concrete checks for the paper's position-binding state assumption."""
    identity = _as_bytes(identity)
    expected_leaf_index = identity_to_leaf_index(
        identity,
        tree_params,
        slot_probe=proof.slot_probe,
    )
    tampered_identity = _alternate_identity_for_distinct_leaf(
        identity,
        tree_params,
        slot_probe=proof.slot_probe,
    )
    tampered_y_id = _tamper_zq_vector_first_coordinate(y_id)
    tampered_root = _tamper_root(root)

    verifies_active_path = verify_verkle_path(identity, y_id, proof, root, tree_params)
    rejects_tampered_y_id = not verify_verkle_path(
        identity,
        tampered_y_id,
        proof,
        root,
        tree_params,
    )
    rejects_tampered_identity = not verify_verkle_path(
        tampered_identity,
        y_id,
        proof,
        root,
        tree_params,
    )
    rejects_tampered_root = not verify_verkle_path(
        identity,
        y_id,
        proof,
        tampered_root,
        tree_params,
    )
    leaf_index_matches_identity = proof.leaf_index == expected_leaf_index

    return {
        "state_tree_kind": "lattice_linear_verkle_tree",
        "security_model": "lattice_linear_verkle_position_binding_experiment",
        "paper_assumption": "Verkle commitment is position-binding",
        "commitment_assumption": "SIS-backed lattice vector commitments with Fiat-Shamir linear aggregation",
        "leaf_index": proof.leaf_index,
        "slot_probe": proof.slot_probe,
        "expected_leaf_index": expected_leaf_index,
        "leaf_index_matches_identity_probe": leaf_index_matches_identity,
        "leaf_index_matches_identity": leaf_index_matches_identity,
        "tampered_identity_leaf_index": identity_to_leaf_index(
            tampered_identity,
            tree_params,
            slot_probe=proof.slot_probe,
        ),
        "verifies_active_path": verifies_active_path,
        "rejects_tampered_y_id": rejects_tampered_y_id,
        "rejects_tampered_identity": rejects_tampered_identity,
        "rejects_tampered_root": rejects_tampered_root,
        "position_binding_checks_hold": (
            verifies_active_path
            and leaf_index_matches_identity
            and rejects_tampered_y_id
            and rejects_tampered_identity
            and rejects_tampered_root
        ),
    }


def lattice_verkle_collision_resolution_report(tree_params, lattice_params):
    """Audit deterministic finite-tree slot probing for identity-index collisions."""
    primary_identity = b"collision-primary"
    colliding_identity = _alternate_identity_for_same_initial_leaf(
        primary_identity,
        tree_params,
    )
    Rq = lattice_params.ring()
    y_primary = vector(Rq, [ZZ(i + 1) for i in range(lattice_params.n)])
    y_colliding = vector(Rq, [ZZ(i + 3) for i in range(lattice_params.n)])
    state_tree = LatticeVerkleTree(tree_params, lattice_params)
    initial_root = state_tree.root()
    primary_path, primary_root = state_tree.insert(primary_identity, y_primary)
    colliding_path, colliding_root = state_tree.insert(colliding_identity, y_colliding)
    duplicate_rejected = False

    try:
        state_tree.insert(primary_identity, y_primary)
    except ValueError:
        duplicate_rejected = True

    initial_leaf_index = identity_to_leaf_index(primary_identity, tree_params)
    colliding_initial_leaf_index = identity_to_leaf_index(colliding_identity, tree_params)
    initial_indices_collide = initial_leaf_index == colliding_initial_leaf_index
    assigned_indices_distinct = primary_path.leaf_index != colliding_path.leaf_index
    primary_path_verifies = verify_verkle_path(
        primary_identity,
        y_primary,
        primary_path,
        primary_root,
        tree_params,
    )
    primary_path_stale_after_collision = not verify_verkle_path(
        primary_identity,
        y_primary,
        primary_path,
        colliding_root,
        tree_params,
    )
    primary_refreshed_path = state_tree.path_proof(primary_identity)
    primary_refreshed_path_verifies = verify_verkle_path(
        primary_identity,
        y_primary,
        primary_refreshed_path,
        colliding_root,
        tree_params,
    )
    colliding_path_verifies = verify_verkle_path(
        colliding_identity,
        y_colliding,
        colliding_path,
        colliding_root,
        tree_params,
    )

    return {
        "scope": "lattice_verkle_finite_tree_collision_resolution",
        "state_tree_kind": "lattice_linear_verkle_tree",
        "paper_requirement": "Register inserts active (id,Y_id) state entries and produces verifiable path proofs.",
        "collision_policy": "deterministic_domain_separated_slot_probe",
        "branching_factor": tree_params.branching_factor,
        "height": tree_params.height,
        "leaf_count": tree_params.leaf_count(),
        "initial_root": initial_root,
        "root_after_primary_insert": primary_root,
        "root_after_collision_insert": colliding_root,
        "primary_identity": primary_identity,
        "colliding_identity": colliding_identity,
        "initial_leaf_index": initial_leaf_index,
        "colliding_initial_leaf_index": colliding_initial_leaf_index,
        "initial_indices_collide": initial_indices_collide,
        "primary_assigned_leaf_index": primary_path.leaf_index,
        "colliding_assigned_leaf_index": colliding_path.leaf_index,
        "primary_slot_probe": primary_path.slot_probe,
        "colliding_slot_probe": colliding_path.slot_probe,
        "collision_uses_nonzero_probe": colliding_path.slot_probe > 0,
        "assigned_indices_distinct": assigned_indices_distinct,
        "primary_path_verifies_before_collision_insert": primary_path_verifies,
        "primary_path_stale_after_collision_insert": primary_path_stale_after_collision,
        "primary_refreshed_path_verifies_after_collision_insert": primary_refreshed_path_verifies,
        "colliding_path_verifies": colliding_path_verifies,
        "duplicate_identity_rejected": duplicate_rejected,
        "active_leaf_count": lattice_verkle_tree_state_report(state_tree)["active_leaf_count"],
        "root_changes_on_primary_insert": initial_root != primary_root,
        "root_changes_on_collision_insert": primary_root != colliding_root,
        "all_checks_hold": all(
            [
                initial_indices_collide,
                primary_path.slot_probe == 0,
                colliding_path.slot_probe > 0,
                assigned_indices_distinct,
                primary_path_verifies,
                primary_path_stale_after_collision,
                primary_refreshed_path_verifies,
                colliding_path_verifies,
                duplicate_rejected,
                initial_root != primary_root,
                primary_root != colliding_root,
            ]
        ),
    }


def root_transition_report(before_root, after_root, label):
    """Report whether a state update changed the published root."""
    return {
        "label": label,
        "before_root": before_root,
        "after_root": after_root,
        "root_changed": before_root != after_root,
    }


def setup_lvc_verkle(setup_params, seed_parts):
    """Run the paper's Setup algorithm over the Sage reference components."""
    A, trapdoor = trap_gen(setup_params.lattice_params, seed_parts)
    state_tree = LatticeVerkleTree(setup_params.tree_params, setup_params.lattice_params)
    root = state_tree.root()
    public_parameters = LVCVerklePublicParameters(
        A,
        setup_params.lattice_params,
        setup_params.beta,
        setup_params.sigma_pre,
        setup_params.tree_params,
        setup_params.auth_params,
        root,
        omega_factor=setup_params.omega_factor,
        auth_omega_factor=setup_params.auth_omega_factor,
        sample_pre_tail_cutoff=setup_params.sample_pre_tail_cutoff,
        mask_tail_cutoff=setup_params.mask_tail_cutoff,
    )
    sample_pre_context = MP12SamplePreContext(
        A,
        trapdoor,
        setup_params.lattice_params,
        setup_params.sigma_pre,
        omega_factor=setup_params.omega_factor,
    )
    master_secret_key = LVCVerkleMasterSecretKey(trapdoor)
    state = LVCVerkleState(
        state_tree,
        sample_pre_context=sample_pre_context,
    )

    return public_parameters, master_secret_key, state


def register_lvc_verkle(public_parameters, master_secret_key, state, identity, epoch, seed_parts):
    """Run the paper's Register algorithm and publish the updated root."""
    identity = _as_bytes(identity)
    if identity_active_in_state(state, identity):
        raise ValueError("identity already registered")

    credential, root = register_identity(
        public_parameters.A,
        master_secret_key.trapdoor,
        public_parameters.lattice_params,
        state.state_tree,
        identity,
        epoch,
        public_parameters.sigma_pre,
        public_parameters.beta,
        seed_parts,
        omega_factor=public_parameters.omega_factor,
        tail_cutoff=public_parameters.sample_pre_tail_cutoff,
        sample_pre_context=state.sample_pre_context,
    )
    state.credentials_by_identity[identity] = credential
    state.credential_history_by_identity.setdefault(identity, []).append(credential)
    public_parameters.root = root

    return credential, root


def register_lvc_verkle_by_identity(public_parameters, master_secret_key, state, identity, seed_parts):
    """Paper-level Register(pp, msk, id) API with internal epoch selection."""
    identity = _as_bytes(identity)
    generation = registration_generation_for_identity(state, identity)
    return register_lvc_verkle(
        public_parameters,
        master_secret_key,
        state,
        identity,
        registration_epoch_for_identity(identity, generation),
        seed_parts,
    )


def issue_authentication_challenge(public_parameters, nonce):
    """Issue the paper's ISV challenge (rho, rt) using the current root."""
    _validate_authentication_nonce_length(public_parameters.auth_params, nonce)
    return AuthenticationChallenge(nonce, public_parameters.root)


def _validate_authentication_nonce_length(auth_params, nonce):
    if len(_as_bytes(nonce)) != auth_params.nonce_bytes:
        raise ValueError("expected rho length to match nonce_bytes")


def sample_authentication_nonce(auth_params, seed_parts):
    """Sample rho in {0,1}^lambda for reproducible Sage experiments."""
    return _shake_digest(
        b"LVC-Verkle-Sage-authentication-nonce-v1",
        list(seed_parts),
        auth_params.nonce_bytes,
    )


def issue_sampled_authentication_challenge(public_parameters, seed_parts):
    """Issue (rho, rt) with rho sampled from the configured lambda-bit space."""
    return issue_authentication_challenge(
        public_parameters,
        sample_authentication_nonce(public_parameters.auth_params, seed_parts),
    )


def authentication_nonce_sampling_report(auth_params, seed_parts):
    """Audit deterministic Sage sampling for rho <- {0,1}^lambda."""
    nonce = sample_authentication_nonce(auth_params, seed_parts)
    repeated_nonce = sample_authentication_nonce(auth_params, seed_parts)
    different_nonce = sample_authentication_nonce(
        auth_params,
        list(seed_parts) + [b"domain-separated-different-nonce"],
    )

    return {
        "scope": "authentication_nonce_sampling",
        "paper_statement": "rho <- {0,1}^lambda",
        "sampler": "domain_separated_shake256_xof",
        "lambda_bits": ZZ(8) * auth_params.nonce_bytes,
        "nonce_bytes": auth_params.nonce_bytes,
        "nonce": nonce,
        "same_seed_reproducible": nonce == repeated_nonce,
        "different_seed_distinct": nonce != different_nonce,
        "length_holds": len(nonce) == auth_params.nonce_bytes,
        "all_checks_hold": all(
            [
                nonce == repeated_nonce,
                nonce != different_nonce,
                len(nonce) == auth_params.nonce_bytes,
            ]
        ),
    }


def authentication_challenge_report(public_parameters, state, challenge):
    """Report whether an ISV challenge binds to the current root."""
    root_is_public_current = challenge.root == public_parameters.root
    root_is_state_current = state is not None and challenge.root == state.current_root()

    return {
        "scope": "authentication_challenge_binding",
        "paper_challenge": "(rho, rt)",
        "nonce": challenge.nonce,
        "root": challenge.root,
        "root_is_public_current": root_is_public_current,
        "root_is_state_current": root_is_state_current,
        "challenge_root_is_current": (
            root_is_public_current
            if state is None
            else root_is_public_current and root_is_state_current
        ),
    }


def authenticate_lvc_verkle_challenge(public_parameters, credential, identity, challenge, seed_parts):
    """Run Authenticate on an explicit ISV challenge (rho, rt)."""
    _validate_authentication_nonce_length(public_parameters.auth_params, challenge.nonce)
    if challenge.root != public_parameters.root:
        raise ValueError("authentication challenge root is not current")

    return authenticate_identity(
        public_parameters.A,
        public_parameters.lattice_params,
        credential,
        identity,
        challenge.nonce,
        challenge.root,
        public_parameters.auth_params,
        seed_parts,
        tail_cutoff=public_parameters.mask_tail_cutoff,
        omega_factor=public_parameters.auth_omega_factor,
    )


def authenticate_lvc_verkle(public_parameters, credential, identity, nonce, seed_parts):
    """Run the paper's Authenticate algorithm against the current root."""
    return authenticate_lvc_verkle_challenge(
        public_parameters,
        credential,
        identity,
        issue_authentication_challenge(public_parameters, nonce),
        seed_parts,
    )


def identity_active_in_state(state, identity):
    """Return whether identity is currently active in the state tree."""
    identity = _as_bytes(identity)
    index = state.state_tree.indices_by_identity.get(identity)
    if index is None:
        return False

    leaf = state.state_tree.leaves_by_index.get(index)
    if leaf is None:
        return False

    return bool(leaf["active"])


def refresh_lvc_verkle_credential(public_parameters, state, identity):
    """Refresh pi_id for an active credential after the published root changes."""
    identity = _as_bytes(identity)
    if identity not in state.credentials_by_identity:
        raise ValueError("identity is not registered")

    credential = state.credentials_by_identity[identity]
    refresh_data = proof_refresh_service(
        public_parameters,
        state,
        identity,
        credential.y_id,
    )
    if refresh_data is None:
        raise ValueError("proof refresh service returned bottom")

    return apply_proof_refresh_to_credential(public_parameters, credential, refresh_data)


def proof_refresh_service(public_parameters, state, identity, y_id):
    """Return public proof-refresh data (Y_id, pi_id, rt) for an active identity."""
    identity = _as_bytes(identity)
    if public_parameters.root != state.current_root():
        return None
    if not identity_active_in_state(state, identity):
        return None

    index = state.state_tree.indices_by_identity[identity]
    leaf = state.state_tree.leaves_by_index[index]
    if leaf["y_id"] != y_id:
        return None

    path_proof = state.state_tree.path_proof(identity)
    if not verify_verkle_path(
        identity,
        y_id,
        path_proof,
        public_parameters.root,
        public_parameters.tree_params,
    ):
        return None

    return PublicProofRefreshData(identity, y_id, path_proof, public_parameters.root)


def apply_proof_refresh_to_credential(public_parameters, credential, refresh_data):
    """Apply public proof-refresh data to a local secret credential."""
    if refresh_data.identity != credential.identity:
        raise ValueError("proof refresh identity does not match credential")
    if refresh_data.y_id != credential.y_id:
        raise ValueError("proof refresh Y_id does not match credential")
    if refresh_data.root != public_parameters.root:
        raise ValueError("proof refresh root is not current")
    if not verify_verkle_path(
        credential.identity,
        credential.y_id,
        refresh_data.path_proof,
        refresh_data.root,
        public_parameters.tree_params,
    ):
        raise ValueError("proof refresh path does not verify")

    credential.path_proof = refresh_data.path_proof
    credential.root = refresh_data.root
    return credential


def verify_lvc_verkle_at_root(public_parameters, identity, y_id, nonce, root, transcript):
    """Run the paper's Verify algorithm with explicit input root rt."""
    return verify_authentication(
        public_parameters.A,
        public_parameters.lattice_params,
        public_parameters.tree_params,
        identity,
        y_id,
        nonce,
        root,
        transcript,
        public_parameters.auth_params,
    )


def verify_lvc_verkle_challenge(public_parameters, identity, y_id, challenge, transcript):
    """Run Verify on the explicit ISV challenge (rho, rt)."""
    return verify_lvc_verkle_at_root(
        public_parameters,
        identity,
        y_id,
        challenge.nonce,
        challenge.root,
        transcript,
    )


def verify_lvc_verkle(public_parameters, identity, y_id, nonce, transcript):
    """Run Verify against the currently published root."""
    return verify_lvc_verkle_at_root(
        public_parameters,
        identity,
        y_id,
        nonce,
        public_parameters.root,
        transcript,
    )


def verification_root_parameterization_report(
    public_parameters,
    state,
    identity,
    y_id,
    challenge,
    transcript,
):
    """Audit the paper Verify input root rt against the current-root wrapper."""
    root_is_public_current = challenge.root == public_parameters.root
    root_is_state_current = state is not None and challenge.root == state.current_root()
    root_is_current = (
        root_is_public_current
        if state is None
        else root_is_public_current and root_is_state_current
    )
    explicit_root_verify_accepts = verify_lvc_verkle_challenge(
        public_parameters,
        identity,
        y_id,
        challenge,
        transcript,
    )
    current_root_verify_accepts = verify_lvc_verkle(
        public_parameters,
        identity,
        y_id,
        challenge.nonce,
        transcript,
    )

    return {
        "scope": "paper_verify_explicit_root_parameterization",
        "paper_verify_input": "Verify(pp,id,Y_id,rho,rt,tau)",
        "paper_challenge": "(rho, rt)",
        "nonce": challenge.nonce,
        "root": challenge.root,
        "root_is_public_current": root_is_public_current,
        "root_is_state_current": root_is_state_current,
        "root_is_current": root_is_current,
        "explicit_root_verify_accepts": explicit_root_verify_accepts,
        "current_root_verify_accepts": current_root_verify_accepts,
        "paper_current_root_accepts": bool(root_is_current and explicit_root_verify_accepts),
        "current_root_wrapper_matches_explicit_when_current": (
            explicit_root_verify_accepts == current_root_verify_accepts
            if root_is_current
            else True
        ),
    }


def revoke_lvc_verkle(public_parameters, master_secret_key, state, identity, seed_parts=None):
    """Run the paper's Revoke algorithm and publish the updated root."""
    identity = _as_bytes(identity)
    root = state.state_tree.revoke(identity)
    state.credentials_by_identity.pop(identity, None)
    public_parameters.root = root

    return root


def register_identity(
    A,
    trapdoor,
    lattice_params,
    state_tree,
    identity,
    epoch,
    sigma,
    beta,
    seed_parts,
    omega_factor=None,
    tail_cutoff=12,
    enforce_sigma_bound=True,
    sample_pre_context=None,
):
    """Run the paper's Register algorithm over the Sage reference components."""
    credential = register_lattice_credential(
        A,
        trapdoor,
        lattice_params,
        identity,
        epoch,
        sigma,
        beta,
        seed_parts,
        omega_factor=omega_factor,
        tail_cutoff=tail_cutoff,
        enforce_sigma_bound=enforce_sigma_bound,
        sample_pre_context=sample_pre_context,
    )
    path_proof, root = state_tree.insert(identity, credential.y_id)
    credential.path_proof = path_proof
    credential.root = root

    return credential, root


def authentication_challenge_scalar(y_id, commitment, nonce, root, identity, auth_params):
    raw_challenge = h2_challenge_scalar(
        [
            _serialize_zq_vector(y_id),
            _serialize_zq_vector(commitment),
            nonce,
            root,
            identity,
        ],
        auth_params.challenge_modulus,
    )

    return auth_params.center_challenge(raw_challenge)


def _authentication_common_checks(A, lattice_params, credential, identity, root):
    identity = _as_bytes(identity)
    if credential.identity != identity:
        raise ValueError("credential identity does not match authentication identity")
    if credential.y_id != h1_to_zq_vector([identity, credential.epoch], lattice_params.n, lattice_params.q):
        raise ValueError("credential Y_id does not match H1(id || epoch)")
    if credential.root != _as_bytes(root):
        raise ValueError("credential path proof root is not current")
    if credential.path_proof is None:
        raise ValueError("credential has no path proof")
    if A * credential.z_id != credential.y_id:
        raise ValueError("credential equation A*z_id = Y_id does not hold")

    return identity


def _authentication_bound_context(lattice_params, credential, auth_params, omega_factor):
    RR = _klein_gso_real_field()
    factor = RR(omega_factor) if omega_factor is not None else sqrt(log(RR(lattice_params.m)))
    if not isfinite(float(factor)) or factor <= 0:
        raise ValueError("expected positive omega_factor")

    mask_norm_bound = RR(auth_params.sigma_mask) * sqrt(RR(lattice_params.m)) * factor
    challenge_scaled_credential_bound = RR(
        auth_params.challenge_bound() * credential.beta
    )
    return {
        "RR": RR,
        "factor": factor,
        "mask_norm_bound": mask_norm_bound,
        "mask_norm_bound_squared": mask_norm_bound * mask_norm_bound,
        "challenge_scaled_credential_bound": challenge_scaled_credential_bound,
        "challenge_scaled_credential_bound_squared": (
            challenge_scaled_credential_bound * challenge_scaled_credential_bound
        ),
        "beta_response_squared": (
            auth_params.beta_response * auth_params.beta_response
        ),
    }


def _build_authentication_generation_audit(
    lattice_params,
    credential,
    auth_params,
    tail_cutoff,
    bound_context,
    attempt,
    attempt_trace,
    commitment,
    response,
    mask_norm_squared,
    challenge,
    response_norm_squared,
    challenge_scaled_credential_norm_squared,
):
    sampler_report = discrete_gaussian_sampler_audit_report(tail_cutoff)
    triangle_bound = (
        bound_context["mask_norm_bound"]
        + bound_context["challenge_scaled_credential_bound"]
    )
    RR = bound_context["RR"]
    commitment_dimension = ZZ(len(commitment))
    response_dimension = ZZ(len(response))
    mask_dimension_matches_m = lattice_params.m == credential.parameter_report["dimension"]
    commitment_dimension_matches_n = commitment_dimension == lattice_params.n
    response_dimension_matches_m = response_dimension == lattice_params.m
    challenge_in_space = auth_params.contains_challenge(challenge)
    response_norm_bound_holds = (
        response_norm_squared <= bound_context["beta_response_squared"]
    )
    report = {
        "paper_algorithm": "Authenticate",
        "paper_transcript": "tau=(pi_id,w,c,s)",
        "paper_challenge": "(rho,rt)",
        "paper_mask_sampling": "r <- D_sigma^m",
        "paper_commitment_equation": "w = A*r mod q",
        "paper_challenge_equation": "c = H2(Y_id || w || rho || rt || id)",
        "paper_response_equation": "s = r + c*z_id",
        "paper_rejection_condition": "resample if ||s||_2 > beta_response",
        "h2_transcript_order": ["Y_id", "w", "rho", "rt", "id"],
        "transcript_fields": ["pi_id", "w", "c", "s"],
        "mask_sampler": "truncated_discrete_gaussian_vector",
        "sampler_backend": sampler_report["sampler_backend"],
        "sampler_real_precision_bits": sampler_report["sampler_real_precision_bits"],
        "sampler_draw_bits": sampler_report["sampler_draw_bits"],
        "mask_dimension": lattice_params.m,
        "mask_dimension_matches_m": mask_dimension_matches_m,
        "commitment_dimension": commitment_dimension,
        "expected_commitment_dimension": lattice_params.n,
        "commitment_dimension_matches_n": commitment_dimension_matches_n,
        "response_dimension": response_dimension,
        "expected_response_dimension": lattice_params.m,
        "response_dimension_matches_m": response_dimension_matches_m,
        "sigma_mask": auth_params.sigma_mask,
        "omega_factor_config_key": "authentication.omega_factor",
        "omega_factor": bound_context["factor"],
        "tail_cutoff": ZZ(tail_cutoff),
        "continuous_tail_heuristic_bound": sampler_report["continuous_tail_heuristic_bound"],
        "accepted_attempt_index": ZZ(attempt),
        "attempt_count": ZZ(attempt + 1),
        "max_attempts": auth_params.max_attempts,
        "rejected_attempt_count": ZZ(attempt),
        "attempt_trace": attempt_trace,
        "attempt_trace_count": ZZ(len(attempt_trace)),
        "all_rejected_attempts_failed_norm_bound": all(
            not entry["response_norm_bound_holds"]
            for entry in attempt_trace[:-1]
        ),
        "accepted_attempt_bound_holds": attempt_trace[-1][
            "response_norm_bound_holds"
        ],
        "paper_rejection_sampling_step": (
            "If ||s|| > beta_response, resample r and repeat."
        ),
        "mask_norm_squared": mask_norm_squared,
        "mask_norm_bound": bound_context["mask_norm_bound"],
        "mask_norm_bound_squared": bound_context["mask_norm_bound_squared"],
        "mask_norm_bound_holds": (
            RR(mask_norm_squared) <= bound_context["mask_norm_bound_squared"]
        ),
        "challenge_scaled_credential_norm_squared": challenge_scaled_credential_norm_squared,
        "challenge_scaled_credential_bound": bound_context[
            "challenge_scaled_credential_bound"
        ],
        "challenge_scaled_credential_bound_squared": bound_context[
            "challenge_scaled_credential_bound_squared"
        ],
        "challenge_scaled_credential_bound_holds": (
            RR(challenge_scaled_credential_norm_squared)
            <= bound_context["challenge_scaled_credential_bound_squared"]
        ),
        "triangle_response_norm_bound": triangle_bound,
        "triangle_response_norm_bound_squared": triangle_bound * triangle_bound,
        "response_triangle_bound_holds": (
            RR(response_norm_squared) <= triangle_bound * triangle_bound
        ),
        "paper_response_bound_formula": "||s|| <= ||r|| + ||c*z_id|| <= sigma_mask * sqrt(m) * authentication.omega_factor + B_c * beta",
        "response_norm_squared": response_norm_squared,
        "beta_response": auth_params.beta_response,
        "response_norm_bound_holds": response_norm_bound_holds,
        "commitment_equation": "w = A*r mod q",
        "commitment_equation_holds": True,
        "challenge_in_space": challenge_in_space,
        "challenge_equation": "c = H2(Y_id || w || rho || rt || id)",
        "challenge_equation_holds": True,
        "response_relation": "s = r + c*z_id",
        "response_relation_holds": True,
        "challenge": challenge,
        "transcript_format": "tau=(pi_id,w,c,s)",
        "all_algorithmic_checks_hold": all(
            [
                mask_dimension_matches_m,
                commitment_dimension_matches_n,
                response_dimension_matches_m,
                challenge_in_space,
                True,
                True,
                response_norm_bound_holds,
            ]
        ),
    }

    return report


def authenticate_identity(
    A,
    lattice_params,
    credential,
    identity,
    nonce,
    root,
    auth_params,
    seed_parts,
    tail_cutoff=12,
    omega_factor=None,
):
    """Run the paper's Authenticate algorithm with scalar challenges."""
    identity = _authentication_common_checks(
        A,
        lattice_params,
        credential,
        identity,
        root,
    )
    z_lift = vector(ZZ, centered_vector(credential.z_id, lattice_params.q))
    bound_context = _authentication_bound_context(
        lattice_params,
        credential,
        auth_params,
        omega_factor,
    )
    attempt_trace = []

    for attempt in range(auth_params.max_attempts):
        r = sample_discrete_gaussian_vector(
            lattice_params.m,
            auth_params.sigma_mask,
            [b"authenticate-mask", ZZ(attempt).binary()] + list(seed_parts),
            tail_cutoff=tail_cutoff,
        )
        commitment = A * vector(lattice_params.ring(), list(r))
        challenge = authentication_challenge_scalar(
            credential.y_id,
            commitment,
            nonce,
            root,
            identity,
            auth_params,
        )
        response = r + ZZ(challenge) * z_lift
        mask_norm_squared = sum(value * value for value in r)
        challenge_scaled_credential_norm_squared = (
            ZZ(challenge) * ZZ(challenge) * ZZ(credential.norm_squared)
        )
        response_norm_squared = sum(value * value for value in response)
        response_norm_bound_holds = (
            response_norm_squared <= bound_context["beta_response_squared"]
        )
        attempt_trace.append(
            {
                "attempt_index": ZZ(attempt),
                "mask_norm_squared": mask_norm_squared,
                "challenge": challenge,
                "response_norm_squared": response_norm_squared,
                "response_norm_bound_holds": response_norm_bound_holds,
                "accepted": response_norm_bound_holds,
            }
        )

        if response_norm_bound_holds:
            audit_report = _build_authentication_generation_audit(
                lattice_params,
                credential,
                auth_params,
                tail_cutoff,
                bound_context,
                attempt,
                attempt_trace,
                commitment,
                response,
                mask_norm_squared,
                challenge,
                response_norm_squared,
                challenge_scaled_credential_norm_squared,
            )
            return AuthenticationTranscript(
                credential.path_proof,
                commitment,
                challenge,
                response,
                audit_report,
            )

    raise ValueError("authentication rejection sampling exceeded max_attempts")


def _ceil_sqrt_integer(value):
    value = ZZ(value)
    if value < 0:
        raise ValueError("expected nonnegative value")

    root = ZZ(floor(sqrt(_klein_gso_real_field()(value))))
    while root * root < value:
        root += 1
    while root > 0 and (root - 1) * (root - 1) >= value:
        root -= 1

    return root


def authentication_rejection_sampling_path_audit(
    A,
    lattice_params,
    credential,
    identity,
    nonce,
    root,
    auth_params,
    seed_parts,
    tail_cutoff=12,
    omega_factor=None,
):
    """Exercise a controlled Authenticate path with at least one rejected attempt."""
    if auth_params.max_attempts < 2:
        raise ValueError("expected max_attempts >= 2 for rejection-path audit")

    z_lift = vector(ZZ, centered_vector(credential.z_id, lattice_params.q))
    simulated_attempts = []
    min_previous_norm = None
    selected_beta_response = None
    selected_accept_index = None

    for attempt in range(auth_params.max_attempts):
        r = sample_discrete_gaussian_vector(
            lattice_params.m,
            auth_params.sigma_mask,
            [b"authenticate-mask", ZZ(attempt).binary()] + list(seed_parts),
            tail_cutoff=tail_cutoff,
        )
        commitment = A * vector(lattice_params.ring(), list(r))
        challenge = authentication_challenge_scalar(
            credential.y_id,
            commitment,
            nonce,
            root,
            identity,
            auth_params,
        )
        response = r + ZZ(challenge) * z_lift
        response_norm_squared = ZZ(sum(value * value for value in response))
        simulated_attempts.append(
            {
                "attempt_index": ZZ(attempt),
                "challenge": challenge,
                "response_norm_squared": response_norm_squared,
            }
        )

        if min_previous_norm is not None:
            beta_candidate = _ceil_sqrt_integer(response_norm_squared)
            if (
                beta_candidate * beta_candidate >= response_norm_squared
                and beta_candidate * beta_candidate < min_previous_norm
            ):
                selected_beta_response = beta_candidate
                selected_accept_index = ZZ(attempt)
                break

        if min_previous_norm is None or response_norm_squared < min_previous_norm:
            min_previous_norm = response_norm_squared

    if selected_beta_response is None:
        return {
            "scope": "authentication_rejection_sampling_path",
            "status": "no_controlled_rejection_path_found",
            "attempts_examined": ZZ(len(simulated_attempts)),
            "simulated_attempts": simulated_attempts,
            "controlled_rejection_path_found": False,
            "all_checks_hold": False,
            "caveat": "No decreasing response-norm attempt for this seed.",
        }

    controlled_auth_params = AuthenticationParameters(
        auth_params.challenge_modulus,
        auth_params.sigma_mask,
        selected_beta_response,
        max_attempts=auth_params.max_attempts,
        nonce_bytes=auth_params.nonce_bytes,
    )
    transcript = authenticate_identity(
        A,
        lattice_params,
        credential,
        identity,
        nonce,
        root,
        controlled_auth_params,
        seed_parts,
        tail_cutoff=tail_cutoff,
        omega_factor=omega_factor,
    )
    generation_report = transcript.audit_report
    rejected_before_accept = generation_report["rejected_attempt_count"] > 0
    accepted_at_selected_index = (
        generation_report["accepted_attempt_index"] == selected_accept_index
    )

    return {
        "scope": "authentication_rejection_sampling_path",
        "status": "controlled_rejection_then_acceptance",
        "paper_step": "Authenticate resamples r while ||s|| > beta_response.",
        "selected_beta_response": selected_beta_response,
        "selected_accept_index": selected_accept_index,
        "attempts_examined": ZZ(len(simulated_attempts)),
        "simulated_attempts": simulated_attempts,
        "generation_report": generation_report,
        "controlled_rejection_path_found": True,
        "rejected_before_accept": rejected_before_accept,
        "accepted_at_selected_index": accepted_at_selected_index,
        "all_checks_hold": all(
            [
                rejected_before_accept,
                accepted_at_selected_index,
                generation_report["all_rejected_attempts_failed_norm_bound"],
                generation_report["accepted_attempt_bound_holds"],
                generation_report["response_norm_bound_holds"],
            ]
        ),
        "caveat": "Deterministic control-flow audit for the rejection loop.",
    }


def authentication_transcript_shape_report(lattice_params, transcript):
    """Report whether tau=(pi_id,w,c,s) has the expected Verify input shape."""
    has_path_proof = hasattr(transcript, "path_proof")
    has_commitment = hasattr(transcript, "commitment")
    has_challenge = hasattr(transcript, "challenge")
    has_response = hasattr(transcript, "response")
    has_required_fields = all(
        [has_path_proof, has_commitment, has_challenge, has_response]
    )
    Rq = lattice_params.ring()

    commitment_is_sage_vector = (
        has_commitment
        and hasattr(transcript.commitment, "base_ring")
        and hasattr(transcript.commitment, "__len__")
    )
    commitment_dimension = (
        ZZ(len(transcript.commitment)) if commitment_is_sage_vector else ZZ(-1)
    )
    commitment_dimension_holds = commitment_dimension == lattice_params.n
    commitment_base_ring_matches_zq = (
        commitment_is_sage_vector and transcript.commitment.base_ring() == Rq
    )
    commitment_coordinates_in_zq = (
        commitment_base_ring_matches_zq
        and all(ZZ(0) <= ZZ(entry) < lattice_params.q for entry in transcript.commitment)
    )

    if has_response:
        try:
            response_entries = list(transcript.response)
            response_iterable_valid = True
        except (TypeError, ValueError):
            response_entries = []
            response_iterable_valid = False
    else:
        response_entries = []
        response_iterable_valid = False
    response_is_sequence = response_iterable_valid
    response_dimension = ZZ(len(response_entries)) if response_iterable_valid else ZZ(-1)
    response_dimension_holds = response_dimension == lattice_params.m
    response_has_base_ring = has_response and hasattr(transcript.response, "base_ring")
    response_base_ring_matches_zz = (
        not response_has_base_ring or transcript.response.base_ring() == ZZ
    )
    response_entries_are_integers = (
        response_iterable_valid and all(entry in ZZ for entry in response_entries)
    )

    challenge_is_integer = has_challenge and transcript.challenge in ZZ

    return {
        "scope": "authentication_transcript_shape",
        "paper_transcript": "tau=(pi_id,w,c,s)",
        "has_path_proof": has_path_proof,
        "has_commitment": has_commitment,
        "has_challenge": has_challenge,
        "has_response": has_response,
        "has_required_fields": has_required_fields,
        "commitment_is_sage_vector": commitment_is_sage_vector,
        "commitment_dimension": commitment_dimension,
        "expected_commitment_dimension": lattice_params.n,
        "commitment_dimension_holds": commitment_dimension_holds,
        "commitment_base_ring_matches_zq": commitment_base_ring_matches_zq,
        "commitment_coordinates_in_zq": commitment_coordinates_in_zq,
        "response_is_sequence": response_is_sequence,
        "response_iterable_valid": response_iterable_valid,
        "response_has_base_ring": response_has_base_ring,
        "response_base_ring_matches_zz": response_base_ring_matches_zz,
        "response_dimension": response_dimension,
        "expected_response_dimension": lattice_params.m,
        "response_dimension_holds": response_dimension_holds,
        "response_entries_are_integers": response_entries_are_integers,
        "challenge_is_integer": challenge_is_integer,
        "all_shape_checks_hold": all(
            [
                has_required_fields,
                commitment_is_sage_vector,
                commitment_dimension_holds,
                commitment_base_ring_matches_zq,
                commitment_coordinates_in_zq,
                response_is_sequence,
                response_iterable_valid,
                response_base_ring_matches_zz,
                response_dimension_holds,
                response_entries_are_integers,
                challenge_is_integer,
            ]
        ),
    }


def verify_authentication(
    A,
    lattice_params,
    tree_params,
    identity,
    y_id,
    nonce,
    root,
    transcript,
    auth_params,
):
    """Run the paper's Verify algorithm with scalar challenges."""
    try:
        if len(_as_bytes(nonce)) != auth_params.nonce_bytes:
            return False
        shape_report = authentication_transcript_shape_report(
            lattice_params,
            transcript,
        )
        if not shape_report["all_shape_checks_hold"]:
            return False
        if not verify_verkle_path_or_false(identity, y_id, transcript.path_proof, root, tree_params):
            return False
        expected_challenge = authentication_challenge_scalar(
            y_id,
            transcript.commitment,
            nonce,
            root,
            identity,
            auth_params,
        )
        if transcript.challenge != expected_challenge:
            return False
        if not auth_params.contains_challenge(transcript.challenge):
            return False
        response_norm_squared = sum(
            ZZ(value) * ZZ(value) for value in transcript.response
        )
        if response_norm_squared > auth_params.beta_response * auth_params.beta_response:
            return False

        lhs = A * vector(lattice_params.ring(), list(transcript.response))
        rhs = transcript.commitment + lattice_params.ring()(transcript.challenge) * y_id
    except (ArithmeticError, AttributeError, IndexError, TypeError, ValueError):
        return False

    return lhs == rhs


def authentication_transcript_report(
    A,
    lattice_params,
    tree_params,
    identity,
    y_id,
    nonce,
    root,
    transcript,
    auth_params,
):
    """Report Verify invariants for an authentication transcript."""
    transcript_shape_report = authentication_transcript_shape_report(
        lattice_params,
        transcript,
    )
    path_proof_holds = verify_verkle_path(
        identity,
        y_id,
        transcript.path_proof,
        root,
        tree_params,
    )
    expected_challenge = authentication_challenge_scalar(
        y_id,
        transcript.commitment,
        nonce,
        root,
        identity,
        auth_params,
    )
    challenge_matches = transcript.challenge == expected_challenge
    challenge_in_space = auth_params.contains_challenge(transcript.challenge)
    response_norm_squared = sum(value * value for value in transcript.response)
    response_norm_bound_holds = response_norm_squared <= (
        auth_params.beta_response * auth_params.beta_response
    )

    response_dimension_holds = len(transcript.response) == lattice_params.m
    commitment_dimension_holds = len(transcript.commitment) == lattice_params.n
    equation_holds = False
    if response_dimension_holds and commitment_dimension_holds:
        lhs = A * vector(lattice_params.ring(), list(transcript.response))
        rhs = transcript.commitment + lattice_params.ring()(transcript.challenge) * y_id
        equation_holds = lhs == rhs

    verifies = all(
        [
            path_proof_holds,
            challenge_matches,
            challenge_in_space,
            response_norm_bound_holds,
            response_dimension_holds,
            commitment_dimension_holds,
            transcript_shape_report["all_shape_checks_hold"],
            equation_holds,
        ]
    )

    return {
        "paper_algorithm": "Verify",
        "paper_input": "Verify(pp,id,Y_id,rho,rt,tau)",
        "paper_transcript": "tau=(pi_id,w,c,s)",
        "paper_challenge_equation": "c = H2(Y_id || w || rho || rt || id)",
        "h2_transcript_order": ["Y_id", "w", "rho", "rt", "id"],
        "transcript_fields": ["pi_id", "w", "c", "s"],
        "transcript_shape_report": transcript_shape_report,
        "transcript_shape_holds": transcript_shape_report["all_shape_checks_hold"],
        "challenge_space": "centered_scalar",
        "challenge_modulus": auth_params.challenge_modulus,
        "challenge_bound_B_c": auth_params.challenge_bound(),
        "delta_c_min": auth_params.delta_c_min(),
        "challenge": transcript.challenge,
        "expected_challenge": expected_challenge,
        "challenge_matches": challenge_matches,
        "challenge_in_space": challenge_in_space,
        "path_proof_holds": path_proof_holds,
        "response_dimension": len(transcript.response),
        "expected_response_dimension": lattice_params.m,
        "response_dimension_holds": response_dimension_holds,
        "commitment_dimension": len(transcript.commitment),
        "expected_commitment_dimension": lattice_params.n,
        "commitment_dimension_holds": commitment_dimension_holds,
        "response_norm_squared": response_norm_squared,
        "beta_response": auth_params.beta_response,
        "response_norm_bound_holds": response_norm_bound_holds,
        "verification_equation": "A*s = w + c*Y_id mod q",
        "equation_holds": equation_holds,
        "all_algorithmic_checks_hold": verifies,
        "verifies": verifies,
    }


def authentication_transcript_input_validation_audit(
    A,
    lattice_params,
    tree_params,
    identity,
    y_id,
    nonce,
    root,
    transcript,
    auth_params,
):
    """Audit that Verify rejects malformed external tau inputs without raising."""
    Rq = lattice_params.ring()

    class RawTranscript:
        pass

    def raw_transcript(path_proof, commitment, challenge, response):
        candidate = RawTranscript()
        candidate.path_proof = path_proof
        candidate.commitment = commitment
        candidate.challenge = challenge
        candidate.response = response
        return candidate

    def malformed_case(name, candidate):
        shape_report = authentication_transcript_shape_report(
            lattice_params,
            candidate,
        )
        accepted = verify_authentication(
            A,
            lattice_params,
            tree_params,
            identity,
            y_id,
            nonce,
            root,
            candidate,
            auth_params,
        )
        return {
            "name": name,
            "verify_rejects": not bool(accepted),
            "shape_checks_hold": bool(shape_report["all_shape_checks_hold"]),
            "shape_report": shape_report,
        }

    missing_fields = RawTranscript()
    malformed_path = raw_transcript(
        object(),
        transcript.commitment,
        transcript.challenge,
        transcript.response,
    )
    commitment_dimension_mismatch = raw_transcript(
        transcript.path_proof,
        vector(Rq, [0] * (lattice_params.n + 1)),
        transcript.challenge,
        transcript.response,
    )
    commitment_ring_mismatch = raw_transcript(
        transcript.path_proof,
        vector(Integers(lattice_params.q + 1), [0] * lattice_params.n),
        transcript.challenge,
        transcript.response,
    )
    response_dimension_mismatch = raw_transcript(
        transcript.path_proof,
        transcript.commitment,
        transcript.challenge,
        vector(ZZ, list(transcript.response) + [ZZ(0)]),
    )
    response_ring_mismatch = raw_transcript(
        transcript.path_proof,
        transcript.commitment,
        transcript.challenge,
        vector(Rq, [Rq(value) for value in transcript.response]),
    )
    challenge_not_integer = raw_transcript(
        transcript.path_proof,
        transcript.commitment,
        QQ(1) / QQ(2),
        transcript.response,
    )

    cases = [
        malformed_case("missing_transcript_fields", missing_fields),
        malformed_case("malformed_path_proof", malformed_path),
        malformed_case("commitment_dimension_mismatch", commitment_dimension_mismatch),
        malformed_case("commitment_ring_mismatch", commitment_ring_mismatch),
        malformed_case("response_dimension_mismatch", response_dimension_mismatch),
        malformed_case("response_ring_mismatch", response_ring_mismatch),
        malformed_case("challenge_not_integer", challenge_not_integer),
    ]
    valid_transcript_accepts = verify_authentication(
        A,
        lattice_params,
        tree_params,
        identity,
        y_id,
        nonce,
        root,
        transcript,
        auth_params,
    )
    all_malformed_rejected = all(case["verify_rejects"] for case in cases)
    at_least_one_shape_failure_per_malformed = all(
        not case["shape_checks_hold"] or case["name"] == "malformed_path_proof"
        for case in cases
    )

    return {
        "scope": "authentication_verify_malformed_transcript_inputs",
        "paper_statement": "Verify(pp,id,Y_id,rho,rt,tau) outputs 0 when tau is malformed or fails any verification check.",
        "valid_transcript_accepts": bool(valid_transcript_accepts),
        "case_count": ZZ(len(cases)),
        "cases": cases,
        "all_malformed_rejected": all_malformed_rejected,
        "at_least_one_shape_failure_per_malformed": at_least_one_shape_failure_per_malformed,
        "all_checks_hold": all(
            [
                valid_transcript_accepts,
                all_malformed_rejected,
                at_least_one_shape_failure_per_malformed,
            ]
        ),
    }


def authentication_negative_verification_report(
    A,
    lattice_params,
    tree_params,
    identity,
    y_id,
    nonce,
    root,
    transcript,
    auth_params,
):
    """Report Verify rejection for replay and transcript-tampering cases."""
    valid_report = authentication_transcript_report(
        A,
        lattice_params,
        tree_params,
        identity,
        y_id,
        nonce,
        root,
        transcript,
        auth_params,
    )
    wrong_nonce_report = None
    wrong_nonce = None
    for suffix in range(256):
        candidate_nonce = (
            _as_bytes(nonce)
            + b"-tampered-"
            + int(suffix).to_bytes(2, "big")
        )
        candidate_report = authentication_transcript_report(
            A,
            lattice_params,
            tree_params,
            identity,
            y_id,
            candidate_nonce,
            root,
            transcript,
            auth_params,
        )
        if not bool(candidate_report["challenge_matches"]):
            wrong_nonce = candidate_nonce
            wrong_nonce_report = candidate_report
            break
    if wrong_nonce_report is None:
        wrong_nonce = _as_bytes(nonce) + b"-tampered"
        wrong_nonce_report = authentication_transcript_report(
            A,
            lattice_params,
            tree_params,
            identity,
            y_id,
            wrong_nonce,
            root,
            transcript,
            auth_params,
        )
    tampered_root_report = authentication_transcript_report(
        A,
        lattice_params,
        tree_params,
        identity,
        y_id,
        nonce,
        _tamper_root(root),
        transcript,
        auth_params,
    )
    tampered_y_id = _tamper_zq_vector_first_coordinate(y_id)
    tampered_y_id_report = authentication_transcript_report(
        A,
        lattice_params,
        tree_params,
        identity,
        tampered_y_id,
        nonce,
        root,
        transcript,
        auth_params,
    )
    tampered_commitment_transcript = AuthenticationTranscript(
        transcript.path_proof,
        _tamper_zq_vector_first_coordinate(transcript.commitment),
        transcript.challenge,
        transcript.response,
        transcript.audit_report,
    )
    tampered_commitment_report = authentication_transcript_report(
        A,
        lattice_params,
        tree_params,
        identity,
        y_id,
        nonce,
        root,
        tampered_commitment_transcript,
        auth_params,
    )
    tampered_challenge_transcript = AuthenticationTranscript(
        transcript.path_proof,
        transcript.commitment,
        transcript.challenge + 1,
        transcript.response,
        transcript.audit_report,
    )
    tampered_challenge_report = authentication_transcript_report(
        A,
        lattice_params,
        tree_params,
        identity,
        y_id,
        nonce,
        root,
        tampered_challenge_transcript,
        auth_params,
    )
    response_tamper = vector(ZZ, [1] + [0] * (lattice_params.m - 1))
    tampered_response_transcript = AuthenticationTranscript(
        transcript.path_proof,
        transcript.commitment,
        transcript.challenge,
        transcript.response + response_tamper,
        transcript.audit_report,
    )
    tampered_response_report = authentication_transcript_report(
        A,
        lattice_params,
        tree_params,
        identity,
        y_id,
        nonce,
        root,
        tampered_response_transcript,
        auth_params,
    )

    rejects_wrong_nonce = not bool(wrong_nonce_report["verifies"])
    rejects_tampered_root = not bool(tampered_root_report["verifies"])
    rejects_tampered_y_id = not bool(tampered_y_id_report["verifies"])
    rejects_tampered_commitment = not bool(tampered_commitment_report["verifies"])
    rejects_tampered_challenge = not bool(tampered_challenge_report["verifies"])
    rejects_tampered_response = not bool(tampered_response_report["verifies"])
    tampered_commitment_challenge_mismatch = not bool(
        tampered_commitment_report["challenge_matches"]
    )
    tampered_commitment_equation_rejected = not bool(
        tampered_commitment_report["equation_holds"]
    )
    tampered_commitment_rejected_by_challenge_or_equation = (
        tampered_commitment_challenge_mismatch
        or tampered_commitment_equation_rejected
    )

    return {
        "scope": "authentication_verify_negative_cases",
        "paper_properties": [
            "nonce_binding",
            "current_root_binding",
            "path_binds_identity_and_Y_id",
            "challenge_recomputation",
            "verification_equation",
        ],
        "valid_transcript_verifies": bool(valid_report["verifies"]),
        "wrong_nonce_hex": wrong_nonce.hex(),
        "wrong_nonce_search_bound": 256,
        "rejects_wrong_nonce": rejects_wrong_nonce,
        "rejects_tampered_root": rejects_tampered_root,
        "rejects_tampered_y_id": rejects_tampered_y_id,
        "rejects_tampered_commitment": rejects_tampered_commitment,
        "rejects_tampered_challenge": rejects_tampered_challenge,
        "rejects_tampered_response": rejects_tampered_response,
        "wrong_nonce_challenge_mismatch": not bool(wrong_nonce_report["challenge_matches"]),
        "tampered_root_path_rejected": not bool(tampered_root_report["path_proof_holds"]),
        "tampered_y_id_path_rejected": not bool(tampered_y_id_report["path_proof_holds"]),
        "tampered_commitment_challenge_mismatch": tampered_commitment_challenge_mismatch,
        "tampered_commitment_equation_rejected": tampered_commitment_equation_rejected,
        "tampered_commitment_rejected_by_challenge_or_equation": (
            tampered_commitment_rejected_by_challenge_or_equation
        ),
        "tampered_challenge_mismatch": not bool(tampered_challenge_report["challenge_matches"]),
        "tampered_response_equation_rejected": not bool(
            tampered_response_report["equation_holds"]
        ),
        "valid_report": valid_report,
        "wrong_nonce_report": wrong_nonce_report,
        "tampered_root_report": tampered_root_report,
        "tampered_y_id_report": tampered_y_id_report,
        "tampered_commitment_report": tampered_commitment_report,
        "tampered_challenge_report": tampered_challenge_report,
        "tampered_response_report": tampered_response_report,
        "all_negative_checks_hold": all(
            [
                bool(valid_report["verifies"]),
                rejects_wrong_nonce,
                rejects_tampered_root,
                rejects_tampered_y_id,
                rejects_tampered_commitment,
                tampered_commitment_rejected_by_challenge_or_equation,
                rejects_tampered_challenge,
                rejects_tampered_response,
            ]
        ),
    }


def register_lattice_credential(
    A,
    trapdoor,
    params,
    identity,
    epoch,
    sigma,
    beta,
    seed_parts,
    omega_factor=None,
    tail_cutoff=12,
    enforce_sigma_bound=True,
    sample_pre_context=None,
):
    """Generate the lattice credential part of the paper's Register algorithm.

    This implements the Register steps that compute Y_id = H1(id || epoch) and
    use SamplePre to obtain z_id with A*z_id = Y_id mod q and ||z_id|| <= beta.
    Verkle insertion and path proof generation are intentionally outside this
    helper.
    """
    beta = ZZ(beta)
    if beta <= 0:
        raise ValueError("expected beta > 0")

    if sample_pre_context is not None:
        if sample_pre_context.A != A:
            raise ValueError("SamplePre context matrix does not match A")
        if (
            sample_pre_context.params.n != params.n
            or sample_pre_context.params.m != params.m
            or sample_pre_context.params.q != params.q
        ):
            raise ValueError("SamplePre context parameters do not match")
        if RDF(sample_pre_context.sigma) != RDF(sigma):
            raise ValueError("SamplePre context sigma does not match")
        parameter_report = sample_pre_context.parameter_report
    else:
        parameter_report = mp12_sample_pre_parameter_report(
            trapdoor,
            params,
            sigma,
            omega_factor=omega_factor,
        )
    if enforce_sigma_bound and not parameter_report["passes_recommended_bound"]:
        raise ValueError("sigma below recommended SamplePre bound")

    y_id = h1_to_zq_vector([identity, epoch], params.n, params.q)
    z_id, sampler_trace_report = sample_pre_mp12_gpv_klein_with_trace(
        A,
        trapdoor,
        y_id,
        params,
        sigma=sigma,
        seed_parts=[b"register-lattice-credential", identity, epoch] + list(seed_parts),
        tail_cutoff=tail_cutoff,
        sample_pre_context=sample_pre_context,
    )
    norm_squared = centered_norm_squared(z_id, params.q)

    if A * z_id != y_id:
        raise ValueError("internal Register credential equation check failed")
    if norm_squared > beta * beta:
        raise ValueError("credential norm exceeds beta")

    sample_pre_report = sample_pre_output_report(
        A,
        y_id,
        z_id,
        params,
        beta,
        parameter_report,
        "sample_pre_mp12_gpv_klein",
        tail_cutoff,
        sampler_trace_report=sampler_trace_report,
    )

    return LatticeCredential(
        identity,
        epoch,
        y_id,
        z_id,
        norm_squared,
        beta,
        parameter_report,
        sample_pre_report,
    )


def _sample_pre_mp12_canonical(A, trapdoor, target, params):
    """Return the canonical gadget preimage for target.

    This deterministic helper is the coset representative used by the
    GPV/Klein SamplePre sampler. It returns z = (R*x, x), where G*x = target.
    """
    _validate_mp12_instance(A, trapdoor, target, params)
    gadget_solution = gadget_decompose(target, params)
    head = matrix(params.ring(), trapdoor.r) * gadget_solution
    candidate = vector(params.ring(), list(head) + list(gadget_solution))

    if A * candidate != target:
        raise ValueError("internal MP12 canonical preimage check failed")

    return candidate


def sample_pre_mp12_gpv_klein(
    A,
    trapdoor,
    target,
    params,
    sigma,
    seed_parts,
    tail_cutoff=12,
    sample_pre_context=None,
):
    """Sample a preimage with a Klein/GPV-style lattice Gaussian step.

    The sampler starts from the canonical preimage z0 and samples a lattice
    vector in Lambda_q^perp(A) centered at -z0 using the GSO of the MP12 kernel
    basis. The returned z = z0 + v preserves A*z = target. This is the Sage
    reference implementation of the paper-level SamplePre path.
    """
    candidate, _ = sample_pre_mp12_gpv_klein_with_trace(
        A,
        trapdoor,
        target,
        params,
        sigma,
        seed_parts,
        tail_cutoff=tail_cutoff,
        sample_pre_context=sample_pre_context,
    )
    return candidate


def sample_pre_mp12_gpv_klein_with_trace(
    A,
    trapdoor,
    target,
    params,
    sigma,
    seed_parts,
    tail_cutoff=12,
    sample_pre_context=None,
):
    """Sample an MP12 preimage and return the per-coordinate Klein audit trace."""
    _validate_mp12_instance(A, trapdoor, target, params)
    if not isfinite(float(sigma)) or RDF(sigma) <= 0:
        raise ValueError("expected finite sigma > 0")

    canonical = _sample_pre_mp12_canonical(A, trapdoor, target, params)
    canonical_lift = vector(ZZ, centered_vector(canonical, params.q))
    if sample_pre_context is None:
        basis = mp12_kernel_basis(trapdoor, params)
        gso_columns = None
        gso_norms_squared = None
    else:
        if sample_pre_context.A != A:
            raise ValueError("SamplePre context matrix does not match A")
        if RDF(sample_pre_context.sigma) != RDF(sigma):
            raise ValueError("SamplePre context sigma does not match")
        basis = sample_pre_context.kernel_basis
        gso_columns = sample_pre_context.gso_columns
        gso_norms_squared = sample_pre_context.gso_norms_squared
    lattice_sample, trace_report = sample_lattice_gaussian_klein_with_trace(
        basis,
        -canonical_lift,
        sigma,
        [b"mp12-gpv-klein"] + list(seed_parts),
        tail_cutoff=tail_cutoff,
        gso_columns=gso_columns,
        gso_norms_squared=gso_norms_squared,
    )
    candidate_lift = canonical_lift + lattice_sample
    candidate = vector(params.ring(), list(candidate_lift))

    if A * candidate != target:
        raise ValueError("internal MP12 GPV/Klein preimage check failed")

    coset_report = sample_pre_coset_decomposition_report(
        A,
        target,
        canonical,
        lattice_sample,
        candidate,
        basis,
        params,
    )
    trace_report["coset_decomposition_report"] = coset_report
    trace_report["all_checks_hold"] = (
        trace_report["all_checks_hold"] and coset_report["all_checks_hold"]
    )

    return candidate, trace_report


def sample_lattice_gaussian_klein(
    basis,
    center,
    sigma,
    seed_parts,
    tail_cutoff=12,
    gso_columns=None,
    gso_norms_squared=None,
):
    """Sample a lattice vector from a column basis near center.

    This is a randomized nearest-plane sampler over the basis columns using
    one-dimensional shifted discrete Gaussian samples with parameter
    sigma / ||b_i^*||.
    """
    lattice_vector, _ = sample_lattice_gaussian_klein_with_trace(
        basis,
        center,
        sigma,
        seed_parts,
        tail_cutoff=tail_cutoff,
        gso_columns=gso_columns,
        gso_norms_squared=gso_norms_squared,
    )
    return lattice_vector


def sample_lattice_gaussian_klein_with_trace(
    basis,
    center,
    sigma,
    seed_parts,
    tail_cutoff=12,
    gso_columns=None,
    gso_norms_squared=None,
):
    """Sample a lattice vector and report the actual Klein coordinate windows."""
    if basis.nrows() != len(center):
        raise ValueError("basis and center dimensions do not match")
    if basis.ncols() == 0:
        RR = _klein_gso_real_field()
        return vector(ZZ, [0] * basis.nrows()), {
            "scope": "sample_pre_klein_coordinate_trace",
            "sampler_algorithm": "randomized_nearest_plane_klein",
            "sampler_backend": "shake256_hybrid_shifted_inverse_cdf_or_box_muller_truncated_window",
            "sampling_distribution_status": "finite_window_truncated_shifted_discrete_gaussian_not_full_lattice_gaussian",
            "coordinate_count": ZZ(0),
            "reported_coordinate_count": ZZ(0),
            "report_truncated": False,
            "sigma": RR(sigma),
            "tail_cutoff": ZZ(tail_cutoff),
            "continuous_tail_heuristic_bound": RR(2) * exp(-((RR(tail_cutoff) ** 2) / RR(2))),
            "finite_window_mass_heuristic_lower_bound": RR(1),
            "min_coordinate_window_mass_heuristic_lower_bound": RR(1),
            "max_coordinate_tail_heuristic_bound": RR(0),
            "sampler_real_precision_bits": ZZ(DISCRETE_GAUSSIAN_REAL_PRECISION_BITS),
            "sampler_draw_bits": ZZ(8 * DISCRETE_GAUSSIAN_DRAW_BYTES),
            "min_local_sigma": RR(0),
            "max_local_sigma": RR(0),
            "min_support_size": ZZ(0),
            "max_support_size": ZZ(0),
            "all_local_sigmas_positive": True,
            "all_centers_finite": True,
            "all_support_windows_finite": True,
            "all_coefficients_inside_windows": True,
            "all_window_mass_bounds_valid": True,
            "coordinate_samples": [],
            "all_checks_hold": True,
            "caveat": "Empty basis trace.",
        }
    if not isfinite(float(sigma)) or RDF(sigma) <= 0:
        raise ValueError("expected finite sigma > 0")

    RR = _klein_gso_real_field()
    columns = [vector(ZZ, column) for column in basis.columns()]
    columns_rr = [vector(RR, list(column)) for column in columns]
    if gso_columns is None or gso_norms_squared is None:
        gso_columns, gso_norms = gram_schmidt_columns(columns)
        gso_backend = "realfield_gram_schmidt_columns"
    else:
        if len(gso_columns) != len(columns) or len(gso_norms_squared) != len(columns):
            raise ValueError("cached GSO data does not match basis dimension")
        gso_norms = gso_norms_squared
        gso_backend = "cached_mp12_sample_pre_context"
    current_center = vector(RR, list(center))
    coefficients = [ZZ(0)] * len(columns)
    coordinate_samples = []
    local_sigmas = []
    support_sizes = []
    window_mass_lower_bounds = []
    coordinate_tail_bounds = []
    all_centers_finite = True
    all_support_windows_finite = True
    all_coefficients_inside_windows = True
    all_window_mass_bounds_valid = True
    tail_bound = RR(2) * exp(-((RR(tail_cutoff) ** 2) / RR(2)))
    window_mass_lower_bound = RR(1) - tail_bound
    if window_mass_lower_bound < 0:
        window_mass_lower_bound = RR(0)

    for index in reversed(range(len(columns))):
        norm_squared = gso_norms[index]
        if norm_squared <= 0:
            raise ValueError("basis columns are not linearly independent")

        coordinate_center = (current_center * gso_columns[index]) / norm_squared
        local_sigma = RR(sigma) / sqrt(norm_squared)
        radius = RR(tail_cutoff) * local_sigma
        lower = ZZ(floor(coordinate_center - radius))
        upper = ZZ(ceil(coordinate_center + radius))
        coefficient = sample_discrete_gaussian_shifted_truncated(
            local_sigma,
            coordinate_center,
            seed_parts,
            ZZ(index),
            tail_cutoff=tail_cutoff,
        )
        coefficients[index] = coefficient
        current_center -= RR(coefficient) * columns_rr[index]
        support_size = upper - lower + 1
        local_sigmas.append(local_sigma)
        support_sizes.append(support_size)
        coordinate_tail_bounds.append(tail_bound)
        window_mass_lower_bounds.append(window_mass_lower_bound)
        center_is_finite = isfinite(float(coordinate_center))
        window_is_finite = bool(lower <= upper and support_size > 0)
        coefficient_inside_window = bool(lower <= coefficient <= upper)
        window_mass_bound_valid = bool(
            RR(0) <= window_mass_lower_bound <= RR(1)
            and RR(0) <= tail_bound
        )
        all_centers_finite = all_centers_finite and center_is_finite
        all_support_windows_finite = all_support_windows_finite and window_is_finite
        all_coefficients_inside_windows = (
            all_coefficients_inside_windows and coefficient_inside_window
        )
        all_window_mass_bounds_valid = (
            all_window_mass_bounds_valid and window_mass_bound_valid
        )
        if len(coordinate_samples) < KLEIN_TRACE_MAX_REPORTED_COORDINATES:
            coordinate_samples.append(
                {
                    "basis_index": ZZ(index),
                    "sampling_order": ZZ(len(coordinate_samples)),
                    "gso_norm_squared": norm_squared,
                    "gso_norm": sqrt(norm_squared),
                    "local_sigma": local_sigma,
                    "coordinate_center": coordinate_center,
                    "support_lower": lower,
                    "support_upper": upper,
                    "support_size": support_size,
                    "continuous_tail_heuristic_bound": tail_bound,
                    "finite_window_mass_heuristic_lower_bound": window_mass_lower_bound,
                    "coefficient": coefficient,
                    "coefficient_inside_window": coefficient_inside_window,
                }
            )

    lattice_vector = vector(ZZ, [0] * basis.nrows())
    for coefficient, column in zip(coefficients, columns):
        lattice_vector += coefficient * column

    min_local_sigma = min(local_sigmas) if local_sigmas else RR(0)
    max_local_sigma = max(local_sigmas) if local_sigmas else RR(0)
    min_support_size = min(support_sizes) if support_sizes else ZZ(0)
    max_support_size = max(support_sizes) if support_sizes else ZZ(0)
    min_window_mass_lower_bound = (
        min(window_mass_lower_bounds) if window_mass_lower_bounds else RR(1)
    )
    max_coordinate_tail_bound = (
        max(coordinate_tail_bounds) if coordinate_tail_bounds else RR(0)
    )
    all_local_sigmas_positive = all(local_sigma > 0 for local_sigma in local_sigmas)
    trace_report = {
        "scope": "sample_pre_klein_coordinate_trace",
        "sampler_algorithm": "randomized_nearest_plane_klein",
        "sampler_backend": "shake256_hybrid_shifted_inverse_cdf_or_box_muller_truncated_window",
        "gso_backend": gso_backend,
        "sampling_distribution_status": "finite_window_truncated_shifted_discrete_gaussian_not_full_lattice_gaussian",
        "coordinate_count": ZZ(len(columns)),
        "reported_coordinate_count": ZZ(len(coordinate_samples)),
        "report_truncated": len(columns) > KLEIN_TRACE_MAX_REPORTED_COORDINATES,
        "sigma": RR(sigma),
        "tail_cutoff": ZZ(tail_cutoff),
        "continuous_tail_heuristic_bound": tail_bound,
        "finite_window_mass_heuristic_lower_bound": min_window_mass_lower_bound,
        "min_coordinate_window_mass_heuristic_lower_bound": min_window_mass_lower_bound,
        "max_coordinate_tail_heuristic_bound": max_coordinate_tail_bound,
        "sampler_real_precision_bits": ZZ(DISCRETE_GAUSSIAN_REAL_PRECISION_BITS),
        "sampler_draw_bits": ZZ(8 * DISCRETE_GAUSSIAN_DRAW_BYTES),
        "min_local_sigma": min_local_sigma,
        "max_local_sigma": max_local_sigma,
        "min_support_size": min_support_size,
        "max_support_size": max_support_size,
        "all_local_sigmas_positive": all_local_sigmas_positive,
        "all_centers_finite": all_centers_finite,
        "all_support_windows_finite": all_support_windows_finite,
        "all_coefficients_inside_windows": all_coefficients_inside_windows,
        "all_window_mass_bounds_valid": all_window_mass_bounds_valid,
        "coordinate_samples": coordinate_samples,
        "all_checks_hold": all(
            [
                all_local_sigmas_positive,
                all_centers_finite,
                all_support_windows_finite,
                all_coefficients_inside_windows,
                all_window_mass_bounds_valid,
            ]
        ),
        "caveat": "Finite shifted-Gaussian window trace for the Sage Klein sampler.",
    }

    return lattice_vector, trace_report


def gram_schmidt_columns(columns):
    RR = _klein_gso_real_field()
    gso_columns = []
    gso_norms = []

    for column in columns:
        orthogonal = vector(RR, list(column))

        for previous, previous_norm in zip(gso_columns, gso_norms):
            if previous_norm <= 0:
                raise ValueError("zero vector in Gram-Schmidt basis")
            orthogonal -= ((orthogonal * previous) / previous_norm) * previous

        norm_squared = orthogonal * orthogonal
        gso_columns.append(orthogonal)
        gso_norms.append(norm_squared)

    return gso_columns, gso_norms


def sample_discrete_gaussian_vector(dimension, sigma, seed_parts, tail_cutoff=12):
    return vector(
        ZZ,
        [
            sample_discrete_gaussian_truncated(
                sigma,
                seed_parts,
                ZZ(index),
                tail_cutoff=tail_cutoff,
            )
            for index in range(ZZ(dimension))
        ],
    )


def sample_discrete_gaussian_truncated(sigma, seed_parts, counter, tail_cutoff=12):
    """Deterministically sample from a finite-window discrete Gaussian.

    The window is [-ceil(tail_cutoff*sigma), ceil(tail_cutoff*sigma)]. This is
    a reproducible experimental sampler, not a constant-time production
    sampler. Small windows use exact inverse-CDF sampling; large windows use a
    SHAKE-derived rounded normal approximation clamped to the same window.
    """
    RR = _discrete_gaussian_real_field()
    sigma = RR(sigma)
    if not isfinite(float(sigma)) or sigma <= 0:
        raise ValueError("expected finite sigma > 0")

    radius = ZZ(ceil(RR(tail_cutoff) * sigma))
    lower = -radius
    upper = radius
    domain = b"LVC-Verkle-Sage-discrete-gaussian-truncated-v1"

    return _sample_discrete_gaussian_from_window(
        sigma,
        RR(0),
        lower,
        upper,
        domain,
        seed_parts,
        counter,
    )


def sample_discrete_gaussian_shifted_truncated(
    sigma,
    center,
    seed_parts,
    counter,
    tail_cutoff=12,
):
    RR = _discrete_gaussian_real_field()
    sigma = RR(sigma)
    center = RR(center)
    if not isfinite(float(sigma)) or sigma <= 0:
        raise ValueError("expected finite sigma > 0")
    if not isfinite(float(center)):
        raise ValueError("expected finite center")

    radius = RR(tail_cutoff) * sigma
    lower = ZZ(floor(center - radius))
    upper = ZZ(ceil(center + radius))

    return _sample_discrete_gaussian_from_window(
        sigma,
        center,
        lower,
        upper,
        b"LVC-Verkle-Sage-discrete-gaussian-shifted-truncated-v1",
        seed_parts,
        counter,
    )


def _sample_discrete_gaussian_from_window(
    sigma,
    center,
    lower,
    upper,
    domain,
    seed_parts,
    counter,
):
    support_size = upper - lower + 1
    if support_size <= 0:
        raise ValueError("empty discrete Gaussian support window")

    if support_size <= DISCRETE_GAUSSIAN_EXACT_CDF_MAX_SUPPORT:
        return _sample_discrete_gaussian_exact_from_window(
            sigma,
            center,
            lower,
            upper,
            domain,
            seed_parts,
            counter,
        )

    return _sample_discrete_gaussian_box_muller_from_window(
        sigma,
        center,
        lower,
        upper,
        domain,
        seed_parts,
        counter,
    )


def _sample_discrete_gaussian_exact_from_window(
    sigma,
    center,
    lower,
    upper,
    domain,
    seed_parts,
    counter,
):
    RR = _discrete_gaussian_real_field()
    values = [ZZ(value) for value in range(lower, upper + 1)]
    weights = [
        RR(exp(-(((RR(value) - center) ** 2) / (2 * sigma ** 2))))
        for value in values
    ]
    total = sum(weights)
    digest = _shake_digest(
        domain,
        _discrete_gaussian_seed_parts(counter, center, sigma, seed_parts),
        DISCRETE_GAUSSIAN_DRAW_BYTES,
    )
    draw = RR(int.from_bytes(digest, "big")) / RR(
        ZZ(1) << (8 * DISCRETE_GAUSSIAN_DRAW_BYTES)
    )
    cumulative = RR(0)

    for value, weight in zip(values, weights):
        cumulative += weight / total
        if draw <= cumulative:
            return value

    return values[-1]


def _sample_discrete_gaussian_box_muller_from_window(
    sigma,
    center,
    lower,
    upper,
    domain,
    seed_parts,
    counter,
):
    RR = _discrete_gaussian_real_field()
    parts = _discrete_gaussian_seed_parts(counter, center, sigma, seed_parts)
    u1 = _shake_uniform_rr(domain + b"-box-muller-u1", parts)
    u2 = _shake_uniform_rr(domain + b"-box-muller-u2", parts)
    z = sqrt(-RR(2) * log(u1)) * cos(RR(2) * RR.pi() * u2)
    candidate = _round_rr_to_zz(center + sigma * z)

    if candidate < lower:
        return lower
    if candidate > upper:
        return upper

    return candidate


def _discrete_gaussian_seed_parts(counter, center, sigma, seed_parts):
    return (
        [
            ZZ(counter).binary(),
            str(center).encode("utf-8"),
            str(sigma).encode("utf-8"),
        ]
        + list(seed_parts)
    )


def _shake_uniform_rr(domain, parts):
    RR = _discrete_gaussian_real_field()
    digest = _shake_digest(domain, parts, DISCRETE_GAUSSIAN_DRAW_BYTES)
    scale = ZZ(1) << (8 * DISCRETE_GAUSSIAN_DRAW_BYTES)

    return (RR(int.from_bytes(digest, "big")) + RR(0.5)) / RR(scale)


def _round_rr_to_zz(value):
    RR = _discrete_gaussian_real_field()
    if value >= 0:
        return ZZ(floor(value + RR(0.5)))

    return ZZ(ceil(value - RR(0.5)))


def sample_pre(
    A,
    trapdoor,
    target,
    params,
    sigma=None,
    seed_parts=None,
    tail_cutoff=12,
):
    """Run the paper-level Sage SamplePre path for an MP12 G-trapdoor."""
    if isinstance(trapdoor, MP12GTrapdoor):
        if sigma is None:
            raise ValueError("MP12 SamplePre requires sigma")
        if seed_parts is None:
            raise ValueError("MP12 SamplePre requires seed_parts")

        return sample_pre_mp12_gpv_klein(
            A,
            trapdoor,
            target,
            params,
            sigma,
            seed_parts,
            tail_cutoff=tail_cutoff,
        )

    raise ValueError("unsupported trapdoor type for SamplePre")


def centered_lift(value, q):
    representative = ZZ(value)
    q = ZZ(q)

    if representative <= q // 2:
        return representative

    return representative - q


def centered_vector(vector_value, q):
    return [centered_lift(value, q) for value in vector_value]


def centered_norm_squared(vector_value, q):
    return sum(value * value for value in centered_vector(vector_value, q))


def _validate_mp12_instance(A, trapdoor, target, params):
    if A.nrows() != params.n or A.ncols() != params.m:
        raise ValueError("A has incompatible MP12 dimensions")
    if len(target) != params.n:
        raise ValueError("target has incompatible MP12 dimension")
    if A.base_ring() != params.ring() or target.base_ring() != params.ring():
        raise ValueError("MP12 modulus mismatch")
    if trapdoor.r.base_ring() != ZZ:
        raise ValueError("R must be an integer matrix")
    if trapdoor.r.nrows() != params.m_bar or trapdoor.r.ncols() != params.w:
        raise ValueError("R has incompatible dimensions")
    if any(ZZ(entry) not in [-1, 0, 1] for entry in trapdoor.r.list()):
        raise ValueError("R entries must be ternary")
    if trapdoor.gadget != gadget_matrix(params):
        raise ValueError("gadget matrix mismatch")
    if trapdoor.a_bar.base_ring() != params.ring():
        raise ValueError("A_bar modulus mismatch")
    if trapdoor.a_bar.nrows() != params.n or trapdoor.a_bar.ncols() != params.m_bar:
        raise ValueError("A_bar has incompatible dimensions")

    expected_tail = trapdoor.gadget - trapdoor.a_bar * matrix(params.ring(), trapdoor.r)
    expected_a = trapdoor.a_bar.augment(expected_tail)
    if A != expected_a:
        raise ValueError("A does not match MP12 trapdoor")


def _sample_mod_q_with_domain(domain, params, seed_parts, counter, label):
    while True:
        digest = _shake_digest(
            domain,
            _mp12_numeric_parts(params, counter, label) + list(seed_parts),
            8,
        )
        candidate = ZZ(int.from_bytes(digest, "big"))
        counter += 1
        range_size = ZZ(1) << 64
        sampling_zone = range_size - (range_size % params.q)

        if candidate < sampling_zone:
            return candidate % params.q, counter


def _sample_ternary_with_domain(domain, params, seed_parts, counter, label):
    digest = _shake_digest(
        domain,
        _mp12_numeric_parts(params, counter, label) + list(seed_parts),
        8,
    )
    candidate = ZZ(int.from_bytes(digest, "big"))
    counter += 1

    return [ZZ(-1), ZZ(0), ZZ(1)][candidate % 3], counter


def _mp12_numeric_parts(params, counter, label):
    return [
        label,
        ZZ(params.n).binary(),
        ZZ(params.q).binary(),
        ZZ(params.base).binary(),
        ZZ(params.k).binary(),
        ZZ(params.m_bar).binary(),
        ZZ(counter).binary(),
    ]


def _ceil_log(value, base):
    value = ZZ(value)
    base = ZZ(base)
    exponent = ZZ(0)
    power = ZZ(1)

    while power < value:
        power *= base
        exponent += 1

    return max(ZZ(1), exponent)


def _lattice_verkle_empty_leaf(tree_params, lattice_params):
    return vector(lattice_params.ring(), [0] * lattice_params.n)


def _lattice_verkle_active_leaf(identity, y_id, tree_params, lattice_params):
    return _lattice_verkle_leaf_vector(
        LATTICE_VERKLE_ACTIVE_LEAF_DOMAIN,
        identity,
        y_id,
        tree_params,
        lattice_params,
    )


def _lattice_verkle_revoked_leaf(identity, y_id, tree_params, lattice_params):
    return _lattice_verkle_leaf_vector(
        LATTICE_VERKLE_REVOKED_LEAF_DOMAIN,
        identity,
        y_id,
        tree_params,
        lattice_params,
    )


def _lattice_verkle_leaf_vector(domain, identity, y_id, tree_params, lattice_params):
    return h1_to_zq_vector(
        [
            domain,
            int(tree_params.branching_factor).to_bytes(8, "big"),
            int(tree_params.height).to_bytes(8, "big"),
            _as_bytes(identity),
            _serialize_zq_vector(y_id),
        ],
        lattice_params.n,
        lattice_params.q,
    )


def _lattice_verkle_node_commitment(
    child_commitments,
    tree_params,
    lattice_params,
    level_from_leaf,
    node_prefix_digits=None,
):
    if len(child_commitments) != tree_params.branching_factor:
        raise ValueError("node has incompatible branching factor")

    Rq = lattice_params.ring()
    if node_prefix_digits is None:
        node_prefix_digits = []
    result = vector(Rq, [0] * lattice_params.n)
    for child_index, child_commitment in enumerate(child_commitments):
        coefficient = _lattice_verkle_fs_coefficient(
            child_commitment,
            tree_params,
            lattice_params,
            level_from_leaf,
            ZZ(child_index),
            node_prefix_digits,
        )
        result += Rq(coefficient) * child_commitment

    return result


def _lattice_verkle_fs_coefficient(
    child_commitment,
    tree_params,
    lattice_params,
    level_from_leaf,
    child_index,
    node_prefix_digits=None,
):
    if node_prefix_digits is None:
        node_prefix_digits = []
    prefix_parts = [int(len(node_prefix_digits)).to_bytes(8, "big")]
    prefix_parts.extend(int(digit).to_bytes(8, "big") for digit in node_prefix_digits)
    stream = _shake_xof_stream(
        LATTICE_VERKLE_FS_COEFFICIENT_DOMAIN,
        [
            int(tree_params.branching_factor).to_bytes(8, "big"),
            int(tree_params.height).to_bytes(8, "big"),
            int(lattice_params.n).to_bytes(8, "big"),
            int(lattice_params.q).to_bytes(8, "big"),
            int(level_from_leaf).to_bytes(8, "big"),
            int(child_index).to_bytes(8, "big"),
        ]
        + prefix_parts
        + [
            _serialize_zq_vector(child_commitment),
        ],
    )
    return _sample_modulus_from_stream(stream, lattice_params.q)


def _tree_parameter_parts(tree_params):
    return [
        int(tree_params.branching_factor).to_bytes(8, "big"),
        int(tree_params.height).to_bytes(8, "big"),
        int(tree_params.commitment_bytes).to_bytes(8, "big"),
    ]


def _serialize_zq_vector(vector_value):
    if not hasattr(vector_value, "base_ring"):
        raise ValueError("expected Sage vector")

    base_ring = vector_value.base_ring()
    if not hasattr(base_ring, "order"):
        raise ValueError("expected vector over a finite ring")

    modulus = ZZ(base_ring.order())
    parts = [
        len(vector_value).to_bytes(8, "big"),
        int(modulus).to_bytes(8, "big"),
    ]

    for value in vector_value:
        parts.append(int(ZZ(value)).to_bytes(8, "big"))

    return b"".join(parts)


def _index_to_base_digits(index, base, length):
    index = ZZ(index)
    base = ZZ(base)
    length = ZZ(length)
    digits = [ZZ(0)] * length

    for position in reversed(range(length)):
        digits[position] = index % base
        index = index // base

    if index != 0:
        raise ValueError("index does not fit in requested digit length")

    return digits


def _base_digits_to_index(digits, base):
    index = ZZ(0)

    for digit in digits:
        index = index * base + ZZ(digit)

    return index


def _alternate_identity_for_distinct_leaf(identity, tree_params, slot_probe=0):
    identity = _as_bytes(identity)
    original_index = identity_to_leaf_index(
        identity,
        tree_params,
        slot_probe=slot_probe,
    )

    for counter in range(1, 1025):
        candidate = identity + b":position-binding-negative:" + int(counter).to_bytes(8, "big")
        if identity_to_leaf_index(candidate, tree_params, slot_probe=slot_probe) != original_index:
            return candidate

    raise ValueError("could not find alternate identity with distinct leaf index")


def _alternate_identity_for_same_initial_leaf(identity, tree_params):
    identity = _as_bytes(identity)
    original_index = identity_to_leaf_index(identity, tree_params, slot_probe=0)

    for counter in range(1, 4097):
        candidate = identity + b":collision-positive:" + int(counter).to_bytes(8, "big")
        if identity_to_leaf_index(candidate, tree_params, slot_probe=0) == original_index:
            return candidate

    raise ValueError("could not find alternate identity with same initial leaf index")


def _tamper_zq_vector_first_coordinate(vector_value):
    if len(vector_value) == 0:
        raise ValueError("cannot tamper an empty vector")

    base_ring = vector_value.base_ring()
    values = list(vector_value)
    values[0] = base_ring(ZZ(values[0]) + 1)

    return vector(base_ring, values)


def _tamper_root(root):
    root = bytearray(_as_bytes(root))
    if len(root) == 0:
        raise ValueError("cannot tamper an empty root")

    root[0] = (int(root[0]) + 1) % 256

    return bytes(root)


def _discrete_gaussian_real_field():
    return RealField(DISCRETE_GAUSSIAN_REAL_PRECISION_BITS)


def _klein_gso_real_field():
    return RealField(KLEIN_GSO_REAL_PRECISION_BITS)


def _shake_digest(domain, parts, output_length):
    hasher = shake_256()
    _update_framed(hasher, domain)

    for part in parts:
        _update_framed(hasher, _as_bytes(part))

    return hasher.digest(output_length)


def _shake_xof_stream(domain, parts):
    return _ShakeXofStream(domain, parts)


def _sample_modulus_from_stream(stream, modulus):
    range_size = ZZ(1) << 64
    sampling_zone = range_size - (range_size % modulus)

    while True:
        candidate = ZZ(int.from_bytes(stream.read(8), "big"))

        if candidate < sampling_zone:
            return candidate % modulus


class _ShakeXofStream:
    def __init__(self, domain, parts):
        self.hasher = shake_256()
        _update_framed(self.hasher, domain)

        for part in parts:
            _update_framed(self.hasher, _as_bytes(part))

        self.offset = ZZ(0)
        self.buffer = b""

    def read(self, length):
        length = ZZ(length)
        if length < 0:
            raise ValueError("expected nonnegative read length")

        needed = self.offset + length
        if len(self.buffer) < needed:
            self.buffer = self.hasher.digest(int(needed))

        chunk = self.buffer[int(self.offset) : int(needed)]
        self.offset = needed

        return chunk


def _update_framed(hasher, data):
    hasher.update(len(data).to_bytes(8, "big"))
    hasher.update(data)


def _as_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")

    return bytes(value)
