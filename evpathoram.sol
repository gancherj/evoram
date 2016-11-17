
// VERSION 2
pragma solidity ^0.4.2;
contract EVPathORAMContract {

    function sig_vrfy(address addr, bytes32 mesg, bytes32 r, bytes32 s) private returns (bool out) {
        return (ecrecover(sha3(mesg), 27, r, s) == addr || ecrecover(sha3(mesg), 28, r, s) == addr);
    }

    function lshift(uint a, uint b) returns (uint) {
        uint exp = 1;
        for (uint i = 0; i < b; i++)
            exp *= 2;
        return a * exp;
    }
    function rshift(uint a, uint b) returns (uint) {
        uint exp = 1;
        for (uint i = 0; i < b; i++)
            exp *= 2;
        return a / exp;
    }

    function GetBucketId(uint assoc, uint lvl) private returns (uint) {
        return lshift(1, lvl) + rshift(assoc, ((tree_depth - 1) - lvl));
    }

    function IsLeftChild(uint bid) private returns (bool) {
        if (bid % 2 == 0) {
            return true;
        }
        else {
            return false;
        }
    }

    function reconstruct_root(bytes32[] path) private returns (bytes32) { // all data ascending leaf to root

        bytes32[] memory cur_bucket = new bytes32[](bytes32_per_block * blocks_per_bucket);
        bytes32 cur_lower_left = 0;
        bytes32 cur_lower_right = 0;
        bytes32 cur_hash = 0;
        uint read_head = 0;


        for (uint k = 1; k < tree_depth; k++) {
            uint256 level = tree_depth - k;
            // read in cur_bucket
            for (uint i = 0; i < bytes32_per_block * blocks_per_bucket; i++) {
                cur_bucket[i] = path[read_head];
                read_head++;
            }

            cur_hash = sha3(cur_bucket, cur_lower_left, cur_lower_right); // TODO find out how this sha works. padding might be different

            if (IsLeftChild(GetBucketId(assoc_leaf, level))) { // next proof bucket is on right
                cur_lower_right = cur_proof[k];
                cur_lower_left = cur_hash;
            }
            else { //next proof bucket is on left
                cur_lower_right = cur_hash;
                cur_lower_left = cur_proof[k];
            }

        }

        // now compute root
        for (uint a = 0; a < bytes32_per_block * blocks_per_bucket; a++) {
                cur_bucket[a] = path[read_head];
                read_head++;
        }
        return sha3(cur_bucket, cur_lower_left, cur_lower_right);

    }

    // Stages

    enum Stage { //stage is what needs to happen next
        ClientHandshake,
        ServerHandshake,
        ClientSubmitRoot,
        ServerSubmitRoot,
        ClientSubmitLeaf,
        ServerSubmitPath,
        ClientSubmitNewPath,
        ServerSubmitNewRoot
    }

    // Modifiers

    modifier advancesStage {
        _;
        cur_stage = Stage(uint(cur_stage) + 1); // this does NOT get called if function returns
    }

    modifier onStage(Stage s) {
        if (cur_stage == s) _;
    }
    modifier onlyBy(address addr) {
        if (msg.sender == addr) _;
    }

    modifier setsTime {
        _;
        saved_time = now;
    }

    // Events

    event Server_handshake_request(address client);
    event Initialized();

    event Server_verify_request(uint256 count);
    event Client_leaf_request();
    event Server_path_request(uint256 x);
    event Client_new_path_request(bytes32[] path, bytes32[] proof);
    event Server_new_path_forward(bytes32[] path, bytes32 newroot, uint newcount, bytes32 newR, bytes32 newS);

    event Cheat_server(string msg);
    event Cheat_client(string msg);
    event Success(bytes32 newR_s, bytes32 newS_s);



    // Persistant state
    uint public tree_depth;
    uint public blocks_per_bucket;
    uint public bytes32_per_block;
    address public server;
    address public client;
    address public admin; // NOTE: only for testing!
    uint timeout;


    // Varying state
    uint saved_time;
    uint public assoc_leaf;
    Stage public cur_stage;
    uint public cur_count_c;
    uint cur_newcount_c;
    bytes32 public cur_root_c;
    bytes32 public cur_newroot_c;
    bytes32[] public cur_proof;


    function EVPathORAMContract() {
        cur_stage = Stage.ClientHandshake;
        admin = msg.sender;
    }

    function destruct() onlyBy(admin) { // NOTE: only for testing!
        selfdestruct(admin);
    }

    function reset() onlyBy(admin) {
        revert_state();
        tree_depth = 0;
        blocks_per_bucket = 0;
        bytes32_per_block = 0;
        server = 0;
        client = 0;
        timeout = 0;
        cur_stage = Stage.ClientHandshake;
    }

    function ClientRegister(address _server, uint _tree_depth, uint _blocks_per_bucket, uint _bytes32_per_block, uint _timeout) onStage(Stage.ClientHandshake) advancesStage {
        server = _server;
        client = msg.sender;
        tree_depth = _tree_depth;
        blocks_per_bucket = _blocks_per_bucket;
        bytes32_per_block = _bytes32_per_block;
        timeout = _timeout;
        Server_handshake_request(client);
    }

    function revert_state() private { // revert all initial state to just after initialization phase
        cur_stage = Stage.ClientSubmitRoot;
        cur_count_c = 0;
        cur_root_c = 0;
        assoc_leaf = 0;
        delete cur_proof;
        cur_newroot_c = 0;
        cur_newcount_c = 0;
        saved_time = now;
    }

    function cheat_client(string msg) private {
        Cheat_client(msg);
        revert_state();
    }

    function cheat_server(string msg) private {
        Cheat_server(msg);
        revert_state();
    }

    function success(bytes32 newr, bytes32 news) private {
        Success(newr, news);
        revert_state();
    }

    function poke() {
        // if client called this, and it's server's turn to go, and (now - time counter) is over a certain amount of time: cheat_server()
        if (msg.sender == client) {
            if (cur_stage == Stage.ServerSubmitRoot || cur_stage == Stage.ServerSubmitPath || cur_stage == Stage.ServerSubmitNewRoot) {
                if ((now - saved_time) > timeout) {
                    cheat_server("timeout");
                    return;
                }
            }
        }

        // if server called this, and it's client's turn to go, and (now - time counter) is over a certain amount of time: cheat_client()
        else if (msg.sender == server) {
            if (cur_stage == Stage.ClientSubmitLeaf|| cur_stage == Stage.ClientSubmitNewPath) {
                if ((now - saved_time) > timeout) {
                    cheat_client("timeout");
                    return;
                }
            }
        }


    }

    function server_handshake() onlyBy(server) onStage(Stage.ServerHandshake) {
        revert_state();
        Initialized();
    }

    function client_submit_root(bytes32 root_c, uint256 count_c, bytes32 R_s, bytes32 S_s)
    onlyBy(client) onStage(Stage.ClientSubmitRoot) advancesStage setsTime {  // R_s and S_s are the two components of the ecc signature
        // we verify sha3(root_c, count_c)
        if (!sig_vrfy(server, sha3(root_c, count_c), R_s, S_s)) {
            cheat_client("bad signature");
            return;
        }
        cur_count_c = count_c;
        cur_root_c = root_c;
        Server_verify_request(count_c);

    }

    function server_submit_root(bytes32 root_s, uint256 count_s, bytes32 R_c, bytes32 S_c)
    onlyBy(server) onStage(Stage.ServerSubmitRoot) advancesStage setsTime {
        if (!sig_vrfy(client, sha3(root_s, count_s), R_c, S_c)) {
            cheat_server("bad signature");
            return;
        }

        if (count_s >= cur_count_c + 2) {
            cheat_client("too old root");
            return;
        }

        else if (count_s != cur_count_c) {
            cheat_server("bad count");
            return;
        }

        Client_leaf_request();
    }

    function client_submit_leaf(uint x)
    onlyBy(client) onStage(Stage.ClientSubmitLeaf) advancesStage setsTime {
        assoc_leaf = x;
        Server_path_request(x);

    }

    function server_submit_path(bytes32[] path, bytes32[] proof)
    onlyBy(server) onStage(Stage.ServerSubmitPath) advancesStage setsTime {

        // path and proof must be the right size

        if (path.length != bytes32_per_block * blocks_per_bucket * tree_depth) {
            throw;
        }
        if (proof.length != tree_depth) {
            throw;
        }



        cur_proof = proof;

        bytes32 rstar = reconstruct_root(path);
        if (rstar != cur_root_c) {
            cheat_server("bad root");
            return;
        }

        Client_new_path_request(path, proof);
    }

    function client_submit_new_path(bytes32[] path, bytes32 newroot_c, uint newcount_c, bytes32 newR_c, bytes32 newS_c)
    onlyBy(client) onStage(Stage.ClientSubmitNewPath) advancesStage setsTime { //count'_c is implicit so i just compute it
        if (newcount_c != cur_count_c + 1) {
            cheat_client("wrong count");
            return;
        }

        if (!sig_vrfy(client, sha3(newroot_c, newcount_c), newR_c, newS_c)) {
            cheat_client("bad signature");

            return;
        }

        bytes32 reconstructed_root = reconstruct_root(path);
        if (reconstructed_root != newroot_c) {
            cheat_client("bad reconstructed_root");
            return;
        }

        cur_newroot_c = reconstructed_root;
        cur_newcount_c = newcount_c;

        Server_new_path_forward(path, newroot_c, newcount_c, newR_c, newS_c);
    }

    function server_submit_new_root(bytes32 newroot_s, uint newcount_s, bytes32 newR_s, bytes32 newS_s)
    onlyBy(server) onStage(Stage.ServerSubmitNewRoot) {
        if (newcount_s != cur_newcount_c) {
            cheat_server("bad count");
            return;
        }
        if (newroot_s != cur_newroot_c) {
            cheat_server("wrong root");
            return;
        }
        if (!sig_vrfy(server, sha3(newroot_s, newcount_s), newR_s, newS_s)) {
            cheat_server("bad signature");
            return;
        }


        success(newR_s, newS_s);
    }
}
