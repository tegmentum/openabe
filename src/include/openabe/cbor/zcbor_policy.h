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
/// \file   zcbor_policy.h
///
/// \brief  ABE-CBOR v1 policy serialization (Boolean AST and MSP formats)
///
/// \author OpenABE Contributors
/// \date   2025-01-04
///

#ifndef __ZCBOR_POLICY_H__
#define __ZCBOR_POLICY_H__

#include <openabe/cbor/zcbor_wrapper.h>
#include <openabe/cbor/zcbor_constants.h>
#include <openabe/cbor/zcbor_attributes.h>
#include <openabe/utils/zpolicy.h>
#include <string>
#include <vector>
#include <cstdint>

namespace oabe {
namespace cbor {

/// \brief  Policy encoding format types
enum class PolicyFormat : uint8_t {
    BOOLEAN_AST = 0,  // Boolean formula as AST in RPN
    MSP = 1           // Monotone Span Program (matrix + rho)
};

/// \brief  RPN token types for Boolean AST encoding
enum class RPNTokenType : uint8_t {
    ATTR = 0,      // Attribute (leaf node)
    AND = 1,       // AND gate
    OR = 2,        // OR gate
    THRESHOLD = 3, // k-of-n threshold gate
    NOT = 4,       // NOT gate (unary)
    XOR = 5,       // XOR gate
    NAND = 6,      // NAND gate
    NOR = 7,       // NOR gate
    XNOR = 8       // XNOR gate
};

/// \brief  Single token in RPN representation
struct RPNToken {
    RPNTokenType type;

    // For ATTR tokens
    AttributeValue attribute;

    // For THRESHOLD tokens
    uint32_t threshold_k;  // k in "k-of-n"

    RPNToken() : type(RPNTokenType::ATTR), threshold_k(0) {}
    RPNToken(RPNTokenType t) : type(t), threshold_k(0) {}
    RPNToken(const AttributeValue& attr) : type(RPNTokenType::ATTR), attribute(attr), threshold_k(0) {}
};

/// \class  PolicySerializer
/// \brief  Serializes and deserializes ABE policies in Boolean AST (RPN) format
class PolicySerializer {
public:
    PolicySerializer();

    // Boolean AST encoding/decoding
    void encodeBooleanAST(ZCBOREncoder& encoder, const OpenABEPolicy& policy);
    std::unique_ptr<OpenABEPolicy> decodeBooleanAST(ZCBORDecoder& decoder);

    // Convert policy tree to RPN token list
    std::vector<RPNToken> treeToRPN(const OpenABETreeNode* root);

    // Convert RPN token list to policy tree
    std::unique_ptr<OpenABETreeNode> rpnToTree(const std::vector<RPNToken>& tokens);

    // Encode/decode RPN token list
    void encodeRPNTokens(ZCBOREncoder& encoder, const std::vector<RPNToken>& tokens);
    std::vector<RPNToken> decodeRPNTokens(ZCBORDecoder& decoder);

private:
    // Helper methods for tree traversal
    void treeToRPNRecursive(const OpenABETreeNode* node, std::vector<RPNToken>& tokens);

    // Map OpenABE gate types to RPN token types
    RPNTokenType gateTypeToRPNType(zGateType gate_type);
    zGateType rpnTypeToGateType(RPNTokenType token_type);

    // Encode/decode individual RPN tokens
    void encodeRPNToken(ZCBOREncoder& encoder, const RPNToken& token);
    RPNToken decodeRPNToken(ZCBORDecoder& decoder);
};

/// \brief  MSP (Monotone Span Program) representation
struct MSPMatrix {
    std::vector<std::vector<int64_t>> matrix;  // Share matrix (rows x cols)
    std::vector<AttributeValue> rho;            // Row-to-attribute mapping

    size_t getNumRows() const { return matrix.size(); }
    size_t getNumCols() const { return matrix.empty() ? 0 : matrix[0].size(); }
};

/// \class  MSPSerializer
/// \brief  Serializes and deserializes policies in MSP format
class MSPSerializer {
public:
    MSPSerializer();

    // MSP encoding/decoding
    void encodeMSP(ZCBOREncoder& encoder, const MSPMatrix& msp);
    MSPMatrix decodeMSP(ZCBORDecoder& decoder);

    // Convert policy tree to MSP
    MSPMatrix treeToMSP(const OpenABETreeNode* root);

    // Convert MSP to policy tree
    std::unique_ptr<OpenABETreeNode> mspToTree(const MSPMatrix& msp);

private:
    // Helper methods for MSP construction
    void treeToMSPRecursive(const OpenABETreeNode* node, MSPMatrix& msp,
                           const std::vector<int64_t>& parent_vector);
};

// Utility functions
std::string policyFormatToString(PolicyFormat format);
std::string rpnTokenTypeToString(RPNTokenType type);

} // namespace cbor
} // namespace oabe

#endif // __ZCBOR_POLICY_H__
