///
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
///
/// This file is part of Zeutro's OpenABE.
///
/// OpenABE is free software: you can redistribute it and/or modify
/// it under the terms of the GNU Affero General Public License as published by
/// the Free Software Foundation, either version 3 of the License, or
/// (at your option) any later version.
///
/// OpenABE is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
/// GNU Affero General Public License for more details.
///
/// You should have received a copy of the GNU Affero General Public
/// License along with OpenABE. If not, see <http://www.gnu.org/licenses/>.
///
/// You can be released from the requirements of the GNU Affero General
/// Public License and obtain additional features by purchasing a
/// commercial license. Buying such a license is mandatory if you
/// engage in commercial activities involving OpenABE that do not
/// comply with the open source requirements of the GNU Affero General
/// Public License. For more information on commerical licenses,
/// visit <http://www.zeutro.com>.
///
/// \file   zcbor_policy.cpp
///
/// \brief  ABE-CBOR v1 policy serialization implementation
///
/// \author OpenABE Contributors
/// \date   2025-01-04
///

#include <openabe/cbor/zcbor_policy.h>
#include <openabe/openabe.h>
#include <stack>
#include <stdexcept>

namespace oabe {
namespace cbor {

// ============================================================================
// PolicySerializer implementation
// ============================================================================

PolicySerializer::PolicySerializer() {
}

void PolicySerializer::encodeBooleanAST(ZCBOREncoder& encoder, const OpenABEPolicy& policy) {
    // Get the root node
    const OpenABETreeNode* root = policy.getRootNode();
    if (!root) {
        throw ZCBORException("Policy has no root node");
    }

    // Convert tree to RPN
    std::vector<RPNToken> tokens = treeToRPN(root);

    // Encode as CBOR array of tokens
    encodeRPNTokens(encoder, tokens);
}

std::unique_ptr<OpenABEPolicy> PolicySerializer::decodeBooleanAST(ZCBORDecoder& decoder) {
    // Decode RPN token list
    std::vector<RPNToken> tokens = decodeRPNTokens(decoder);

    // Convert RPN to tree
    std::unique_ptr<OpenABETreeNode> root = rpnToTree(tokens);

    // Create policy and set root
    std::unique_ptr<OpenABEPolicy> policy(new OpenABEPolicy());
    policy->setRootNode(root.release());

    return policy;
}

std::vector<RPNToken> PolicySerializer::treeToRPN(const OpenABETreeNode* root) {
    std::vector<RPNToken> tokens;
    treeToRPNRecursive(root, tokens);
    return tokens;
}

void PolicySerializer::treeToRPNRecursive(const OpenABETreeNode* node, std::vector<RPNToken>& tokens) {
    if (!node) {
        return;
    }

    zGateType gate_type = static_cast<zGateType>(node->getNodeType());

    // Handle leaf nodes (attributes)
    if (gate_type == GATE_TYPE_LEAF) {
        RPNToken token(RPNTokenType::ATTR);
        token.attribute = AttributeValue(node->getCompleteLabel());
        tokens.push_back(token);
        return;
    }

    // Process children first (post-order traversal for RPN)
    // Cast away const since getNumSubnodes/getSubnode are not const methods
    OpenABETreeNode* non_const_node = const_cast<OpenABETreeNode*>(node);
    uint32_t num_children = non_const_node->getNumSubnodes();
    for (uint32_t i = 0; i < num_children; i++) {
        OpenABETreeNode* child = non_const_node->getSubnode(i);
        treeToRPNRecursive(child, tokens);
    }

    // Then add the operator token
    RPNToken token(gateTypeToRPNType(gate_type));

    // For threshold gates, include the k value
    if (gate_type == GATE_TYPE_THRESHOLD) {
        token.threshold_k = non_const_node->getThresholdValue();
    }

    tokens.push_back(token);
}

std::unique_ptr<OpenABETreeNode> PolicySerializer::rpnToTree(const std::vector<RPNToken>& tokens) {
    std::stack<std::unique_ptr<OpenABETreeNode>> node_stack;

    for (const auto& token : tokens) {
        if (token.type == RPNTokenType::ATTR) {
            // Create leaf node
            std::unique_ptr<OpenABETreeNode> leaf(new OpenABETreeNode(token.attribute.string_value));
            leaf->setNodeType(GATE_TYPE_LEAF);
            node_stack.push(std::move(leaf));
        }
        else {
            // Create operator node
            std::unique_ptr<OpenABETreeNode> op_node(new OpenABETreeNode());
            op_node->setNodeType(rpnTypeToGateType(token.type));

            // Determine number of operands
            uint32_t num_operands = 0;
            if (token.type == RPNTokenType::NOT) {
                num_operands = 1;  // Unary operator
            } else if (token.type == RPNTokenType::THRESHOLD) {
                // For threshold, we need k-of-n, where n is determined by available operands
                // In RPN, the threshold value tells us how many operands to pop
                num_operands = token.threshold_k;
                op_node->setThresholdValue(token.threshold_k);
            } else {
                // Binary/n-ary operators: pop 2 operands by default
                // (In practice, AND/OR can be n-ary, so we might need to adjust)
                num_operands = 2;
            }

            // Check if we have enough operands
            if (node_stack.size() < num_operands) {
                throw ZCBORException("Invalid RPN: not enough operands");
            }

            // Pop operands and add as children (reverse order for correct reconstruction)
            std::vector<std::unique_ptr<OpenABETreeNode>> children;
            for (uint32_t i = 0; i < num_operands; i++) {
                children.push_back(std::move(node_stack.top()));
                node_stack.pop();
            }

            // Add children in reverse order (since we popped them in reverse)
            for (int i = children.size() - 1; i >= 0; i--) {
                op_node->addSubnode(children[i].release());
            }

            node_stack.push(std::move(op_node));
        }
    }

    // Should have exactly one node left (the root)
    if (node_stack.size() != 1) {
        throw ZCBORException("Invalid RPN: multiple root nodes");
    }

    return std::move(node_stack.top());
}

void PolicySerializer::encodeRPNTokens(ZCBOREncoder& encoder, const std::vector<RPNToken>& tokens) {
    // Encode as array of tokens
    encoder.beginArray(tokens.size());

    for (const auto& token : tokens) {
        encodeRPNToken(encoder, token);
    }
}

std::vector<RPNToken> PolicySerializer::decodeRPNTokens(ZCBORDecoder& decoder) {
    std::vector<RPNToken> tokens;

    size_t array_size = decoder.enterArray();
    for (size_t i = 0; i < array_size; i++) {
        tokens.push_back(decodeRPNToken(decoder));
    }

    decoder.exitArray();
    return tokens;
}

void PolicySerializer::encodeRPNToken(ZCBOREncoder& encoder, const RPNToken& token) {
    // Encode token as map: {0: type, 1: value (optional)}
    if (token.type == RPNTokenType::ATTR) {
        // For attributes: {0: 0, 1: attribute_value}
        encoder.beginMap(2);
        encoder.encodeUInt(0);
        encoder.encodeUInt(static_cast<uint32_t>(token.type));
        encoder.encodeUInt(1);
        AttributeSerializer attr_ser;
        attr_ser.encodeAttribute(encoder, token.attribute);
    }
    else if (token.type == RPNTokenType::THRESHOLD) {
        // For threshold: {0: 3, 1: k}
        encoder.beginMap(2);
        encoder.encodeUInt(0);
        encoder.encodeUInt(static_cast<uint32_t>(token.type));
        encoder.encodeUInt(1);
        encoder.encodeUInt(token.threshold_k);
    }
    else {
        // For other operators: {0: type}
        encoder.beginMap(1);
        encoder.encodeUInt(0);
        encoder.encodeUInt(static_cast<uint32_t>(token.type));
    }
}

RPNToken PolicySerializer::decodeRPNToken(ZCBORDecoder& decoder) {
    RPNToken token;

    // Decode map
    size_t map_size = decoder.enterMap();
    if (map_size < 1 || map_size > 2) {
        throw ZCBORException("Invalid RPN token map size");
    }

    // Read type (key 0)
    uint64_t key = decoder.decodeUInt();
    if (key != 0) {
        throw ZCBORException("Expected token type at key 0");
    }
    uint64_t type_val = decoder.decodeUInt();
    token.type = static_cast<RPNTokenType>(type_val);

    // Read value if present (key 1)
    if (map_size == 2) {
        key = decoder.decodeUInt();
        if (key != 1) {
            throw ZCBORException("Expected token value at key 1");
        }

        if (token.type == RPNTokenType::ATTR) {
            // Decode attribute
            AttributeSerializer attr_ser;
            token.attribute = attr_ser.decodeAttribute(decoder);
        }
        else if (token.type == RPNTokenType::THRESHOLD) {
            // Decode threshold k
            token.threshold_k = static_cast<uint32_t>(decoder.decodeUInt());
        }
    }

    decoder.exitMap();
    return token;
}

RPNTokenType PolicySerializer::gateTypeToRPNType(zGateType gate_type) {
    switch (gate_type) {
        case GATE_TYPE_LEAF:      return RPNTokenType::ATTR;
        case GATE_TYPE_AND:       return RPNTokenType::AND;
        case GATE_TYPE_OR:        return RPNTokenType::OR;
        case GATE_TYPE_THRESHOLD: return RPNTokenType::THRESHOLD;
        case GATE_TYPE_NOT:       return RPNTokenType::NOT;
        case GATE_TYPE_XOR:       return RPNTokenType::XOR;
        case GATE_TYPE_NAND:      return RPNTokenType::NAND;
        case GATE_TYPE_NOR:       return RPNTokenType::NOR;
        case GATE_TYPE_XNOR:      return RPNTokenType::XNOR;
        default:
            throw ZCBORException("Unknown gate type");
    }
}

zGateType PolicySerializer::rpnTypeToGateType(RPNTokenType token_type) {
    switch (token_type) {
        case RPNTokenType::ATTR:      return GATE_TYPE_LEAF;
        case RPNTokenType::AND:       return GATE_TYPE_AND;
        case RPNTokenType::OR:        return GATE_TYPE_OR;
        case RPNTokenType::THRESHOLD: return GATE_TYPE_THRESHOLD;
        case RPNTokenType::NOT:       return GATE_TYPE_NOT;
        case RPNTokenType::XOR:       return GATE_TYPE_XOR;
        case RPNTokenType::NAND:      return GATE_TYPE_NAND;
        case RPNTokenType::NOR:       return GATE_TYPE_NOR;
        case RPNTokenType::XNOR:      return GATE_TYPE_XNOR;
        default:
            throw ZCBORException("Unknown RPN token type");
    }
}

// ============================================================================
// MSPSerializer implementation
// ============================================================================

MSPSerializer::MSPSerializer() {
}

void MSPSerializer::encodeMSP(ZCBOREncoder& encoder, const MSPMatrix& msp) {
    // Encode as map: {0: matrix, 1: rho}
    encoder.beginMap(2);

    // Key 0: matrix (array of rows, each row is array of integers)
    encoder.encodeUInt(0);
    encoder.beginArray(msp.getNumRows());
    for (const auto& row : msp.matrix) {
        encoder.beginArray(row.size());
        for (int64_t val : row) {
            encoder.encodeInt(val);
        }
    }

    // Key 1: rho (array of attributes)
    encoder.encodeUInt(1);
    AttributeSerializer attr_ser;
    std::vector<AttributeValue> rho_copy = msp.rho;  // Non-const copy for sorting
    attr_ser.encodeAttributeList(encoder, rho_copy);
}

MSPMatrix MSPSerializer::decodeMSP(ZCBORDecoder& decoder) {
    MSPMatrix msp;

    // Decode map
    size_t map_size = decoder.enterMap();
    if (map_size != 2) {
        throw ZCBORException("Invalid MSP map size");
    }

    // Read matrix (key 0)
    uint64_t key = decoder.decodeUInt();
    if (key != 0) {
        throw ZCBORException("Expected MSP matrix at key 0");
    }
    size_t num_rows = decoder.enterArray();
    for (size_t i = 0; i < num_rows; i++) {
        std::vector<int64_t> row;
        size_t row_size = decoder.enterArray();
        for (size_t j = 0; j < row_size; j++) {
            row.push_back(decoder.decodeInt());
        }
        decoder.exitArray();
        msp.matrix.push_back(row);
    }
    decoder.exitArray();

    // Read rho (key 1)
    key = decoder.decodeUInt();
    if (key != 1) {
        throw ZCBORException("Expected MSP rho at key 1");
    }
    AttributeSerializer attr_ser;
    msp.rho = attr_ser.decodeAttributeList(decoder);

    decoder.exitMap();
    return msp;
}

MSPMatrix MSPSerializer::treeToMSP(const OpenABETreeNode* root) {
    // TODO: Implement policy tree to MSP conversion
    // This requires LSSS (Linear Secret Sharing Scheme) conversion
    throw ZCBORException("MSP conversion not yet implemented");
}

std::unique_ptr<OpenABETreeNode> MSPSerializer::mspToTree(const MSPMatrix& msp) {
    // TODO: Implement MSP to policy tree conversion
    throw ZCBORException("MSP to tree conversion not yet implemented");
}

// ============================================================================
// Utility functions
// ============================================================================

std::string policyFormatToString(PolicyFormat format) {
    switch (format) {
        case PolicyFormat::BOOLEAN_AST: return "boolean-ast";
        case PolicyFormat::MSP: return "msp";
        default: return "unknown";
    }
}

std::string rpnTokenTypeToString(RPNTokenType type) {
    switch (type) {
        case RPNTokenType::ATTR:      return "ATTR";
        case RPNTokenType::AND:       return "AND";
        case RPNTokenType::OR:        return "OR";
        case RPNTokenType::THRESHOLD: return "THRESHOLD";
        case RPNTokenType::NOT:       return "NOT";
        case RPNTokenType::XOR:       return "XOR";
        case RPNTokenType::NAND:      return "NAND";
        case RPNTokenType::NOR:       return "NOR";
        case RPNTokenType::XNOR:      return "XNOR";
        default: return "unknown";
    }
}

} // namespace cbor
} // namespace oabe
