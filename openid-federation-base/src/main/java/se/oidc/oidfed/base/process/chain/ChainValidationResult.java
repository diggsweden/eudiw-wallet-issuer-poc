/*
 * Copyright 2024 OIDC Sweden
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.oidc.oidfed.base.process.chain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.oidc.oidfed.base.data.federation.EntityMetadataInfoClaim;
import se.oidc.oidfed.base.data.federation.EntityStatement;
import se.oidc.oidfed.base.data.federation.TrustMarkClaim;

import java.util.List;

/**
 * Result data from chain validation
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ChainValidationResult {

  /** The validated chain */
  private List<EntityStatement> validatedChain;

  // The declared metadata of the target
  private EntityMetadataInfoClaim declaredMetadata;

  // Process metadata against policy
  private EntityMetadataInfoClaim policyProcessedMetadata;

  // Trust marks for the subject to be validated
  private List<TrustMarkClaim> subjectTrustMarks;

}
