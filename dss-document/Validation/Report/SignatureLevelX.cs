/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas BovÃ© 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

using System.Collections.Generic;
using EU.Europa.EC.Markt.Dss.Validation;
using EU.Europa.EC.Markt.Dss.Validation.Report;
using Sharpen;

namespace EU.Europa.EC.Markt.Dss.Validation.Report
{
	/// <summary>Validation information for level X (CAdES, XAdES).</summary>
	/// <remarks>Validation information for level X (CAdES, XAdES).</remarks>
	/// <version>$Revision: 1887 $ - $Date: 2013-04-23 14:56:09 +0200 (mar., 23 avr. 2013) $
	/// 	</version>
	public class SignatureLevelX : SignatureLevel
	{
		private TimestampVerificationResult[] signatureAndRefsTimestampsVerification;

		private TimestampVerificationResult[] referencesTimestampsVerification;

		public SignatureLevelX(AdvancedSignature signature, Result levelReached) : base(levelReached
			)
		{
		}

		/// <summary>The default constructor for SignatureLevelBES.</summary>
		/// <remarks>The default constructor for SignatureLevelBES.</remarks>
		/// <param name="name"></param>
		/// <param name="signature"></param>
		/// <param name="levelReached"></param>
		public SignatureLevelX(AdvancedSignature signature, Result levelReached, TimestampVerificationResult
			[] signatureAndRefsTimestampsVerification, TimestampVerificationResult[] referencesTimestampsVerification
			) : base(levelReached)
		{
			this.signatureAndRefsTimestampsVerification = signatureAndRefsTimestampsVerification;
			this.referencesTimestampsVerification = referencesTimestampsVerification;
		}

		public SignatureLevelX(AdvancedSignature signature, Result levelReached, IList<TimestampVerificationResult
			> signatureAndRefsTimestampsVerification, IList<TimestampVerificationResult> referencesTimestampsVerification
			) : base(levelReached)
		{
			TimestampVerificationResult[] array1 = new TimestampVerificationResult[signatureAndRefsTimestampsVerification
				.Count];
			this.signatureAndRefsTimestampsVerification = Sharpen.Collections.ToArray(signatureAndRefsTimestampsVerification
				, array1);
			TimestampVerificationResult[] array2 = new TimestampVerificationResult[referencesTimestampsVerification
				.Count];
			this.referencesTimestampsVerification = Sharpen.Collections.ToArray(referencesTimestampsVerification
				, array2);
		}

		/// <returns>the signatureAndRefsTimestampsVerification</returns>
		public virtual TimestampVerificationResult[] GetSignatureAndRefsTimestampsVerification
			()
		{
			return signatureAndRefsTimestampsVerification;
		}

		/// <returns>the referencesTimestampsVerification</returns>
		public virtual TimestampVerificationResult[] GetReferencesTimestampsVerification(
			)
		{
			return referencesTimestampsVerification;
		}
	}
}
