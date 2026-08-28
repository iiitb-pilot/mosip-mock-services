package io.mosip.mock.sbi.devicehelper.finger.slap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.mosip.mock.sbi.SBIConstant;
import io.mosip.mock.sbi.devicehelper.SBICheckState;
import io.mosip.mock.sbi.devicehelper.SBIDeviceHelper;
import io.mosip.mock.sbi.util.ApplicationPropertyHelper;
import io.mosip.mock.sbi.util.BioUtilHelper;
import io.mosip.mock.sbi.util.StringHelper;

public class SBIFingerSlapHelper extends SBIDeviceHelper {

	private static final Logger LOGGER =
			LoggerFactory.getLogger(SBIFingerSlapHelper.class);

	private SBIFingerSlapHelper(int port,
	                            String purpose,
	                            String keystorePath,
	                            String biometricImageType) {

		super(port,
				purpose,
				SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER,
				SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP,
				keystorePath,
				biometricImageType);
	}

	// synchronized method to control simultaneous access
	synchronized public static SBIFingerSlapHelper getInstance(
			int port,
			String purpose,
			String keystorePath,
			String biometricImageType) {

		return new SBIFingerSlapHelper(
				port,
				purpose,
				keystorePath,
				biometricImageType);
	}

	@Override
	public long initDevice() {

		SBIFingerSlapCaptureInfo captureInfo =
				new SBIFingerSlapCaptureInfo();

		captureInfo.initCaptureInfo();
		setCaptureInfo(captureInfo);

		return 0;
	}

	@Override
	public int deInitDevice() {

		if (getCaptureInfo() != null) {
			getCaptureInfo().deInitCaptureInfo();
		}

		setCaptureInfo(null);

		return 0;
	}

	@Override
	public int getLiveStream() {

		byte[] image = getLiveStreamBufferedImage();

		if (image == null || image.length == 0) {
			return -1;
		}

		getCaptureInfo().setImage(image);

		return 0;
	}

	@Override
	public int getBioCapture(boolean isUsedForAuthenication)
			throws Exception {

		String seedName = "";

		/*
		 * AUTOMATIC PROFILE
		 */
		if (this.getProfileId()
				.equalsIgnoreCase(SBIConstant.PROFILE_AUTOMATIC)) {

			int seedValue = -1;

			/*
			 * AUTHENTICATION
			 */
			if (this.getPurpose()
					.equalsIgnoreCase(SBIConstant.PURPOSE_AUTH)) {

				if (ApplicationPropertyHelper.getPropertyKeyValue(
						SBIConstant.MOSIP_BIOMETRIC_AUTH_SEED_FINGER) != null) {

					seedValue = Integer.parseInt(
							ApplicationPropertyHelper.getPropertyKeyValue(
									SBIConstant.MOSIP_BIOMETRIC_AUTH_SEED_FINGER));

					seedName = String.format(
							"%04d",
							getRandomNumberForSeed(seedValue)).trim();
				}
			}

			/*
			 * REGISTRATION
			 */
			else if (this.getPurpose()
					.equalsIgnoreCase(SBIConstant.PURPOSE_REGISTRATION)) {

				if (ApplicationPropertyHelper.getPropertyKeyValue(
						SBIConstant.MOSIP_BIOMETRIC_REGISTRATION_SEED_FINGER)
						!= null) {

					seedValue = Integer.parseInt(
							ApplicationPropertyHelper.getPropertyKeyValue(
									SBIConstant.MOSIP_BIOMETRIC_REGISTRATION_SEED_FINGER));

					seedName = String.format(
							"%04d",
							getRandomNumberForSeed(seedValue)).trim();
				}
			}
		}

		/*
		 * DEVICE SUB ID
		 *
		 * 1  = LEFT SLAP
		 * 2  = RIGHT SLAP
		 * 3  = TWO THUMBS
		 *
		 * 4  = LEFT INDEX
		 * 5  = RIGHT INDEX
		 * 6  = LEFT MIDDLE
		 * 7  = RIGHT MIDDLE
		 * 8  = LEFT RING
		 * 9  = RIGHT RING
		 * 10 = LEFT LITTLE
		 * 11 = RIGHT LITTLE
		 * 12 = LEFT THUMB
		 * 13 = RIGHT THUMB
		 */

		switch (getDeviceSubId()) {

			/*
			 * =========================
			 * LEFT SLAP
			 * ID = 1
			 * =========================
			 */
			case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT:

				setBioCaptureFingerprintForSubTypeLeft(
						isUsedForAuthenication,
						seedName);

				break;

			/*
			 * =========================
			 * RIGHT SLAP
			 * ID = 2
			 * =========================
			 */
			case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT:

				setBioCaptureFingerprintForSubTypeRight(
						isUsedForAuthenication,
						seedName);

				break;

			/*
			 * =========================
			 * TWO THUMBS
			 * ID = 3
			 * =========================
			 */
			case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_THUMB:

				setBioCaptureFingerprintForSubTypeThumb(
						isUsedForAuthenication,
						seedName);

				break;

			/*
			 * =========================
			 * LEFT INDEX
			 * ID = 4
			 * =========================
			 */
			case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_INDEX:

				setBioCaptureFingerprintForLeftIndex(
						isUsedForAuthenication,
						seedName);

				break;

			/*
			 * =========================
			 * RIGHT INDEX
			 * ID = 5
			 * =========================
			 */
			case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_INDEX:

				setBioCaptureFingerprintForRightIndex(
						isUsedForAuthenication,
						seedName);

				break;

			/*
			 * =========================
			 * LEFT MIDDLE
			 * ID = 6
			 * =========================
			 */
			case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_MIDDLE:

				setBioCaptureFingerprintForLeftMiddle(
						isUsedForAuthenication,
						seedName);

				break;

			/*
			 * =========================
			 * RIGHT MIDDLE
			 * ID = 7
			 * =========================
			 */
			case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_MIDDLE:

				setBioCaptureFingerprintForRightMiddle(
						isUsedForAuthenication,
						seedName);

				break;

			/*
			 * =========================
			 * LEFT RING
			 * ID = 8
			 * =========================
			 */
			case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_RING:

				setBioCaptureFingerprintForLeftRing(
						isUsedForAuthenication,
						seedName);

				break;

			/*
			 * =========================
			 * RIGHT RING
			 * ID = 9
			 * =========================
			 */
			case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_RING:

				setBioCaptureFingerprintForRightRing(
						isUsedForAuthenication,
						seedName);

				break;

			/*
			 * =========================
			 * LEFT LITTLE
			 * ID = 10
			 * =========================
			 */
			case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_LITTLE:

				setBioCaptureFingerprintForLeftLittle(
						isUsedForAuthenication,
						seedName);

				break;

			/*
			 * =========================
			 * RIGHT LITTLE
			 * ID = 11
			 * =========================
			 */
			case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_LITTLE:

				setBioCaptureFingerprintForRightLittle(
						isUsedForAuthenication,
						seedName);

				break;

			/*
			 * =========================
			 * LEFT THUMB
			 * ID = 12
			 * =========================
			 */
			case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_THUMB:

				setBioCaptureFingerprintForLeftThumb(
						isUsedForAuthenication,
						seedName);

				break;

			/*
			 * =========================
			 * RIGHT THUMB
			 * ID = 13
			 * =========================
			 */
			case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_THUMB:

				setBioCaptureFingerprintForRightThumb(
						isUsedForAuthenication,
						seedName);

				break;

			default:

				LOGGER.error(
						"Unsupported finger deviceSubId: {}",
						getDeviceSubId());

				break;
		}

		return 0;
	}

	/*
	 * ============================================================
	 * LEFT INDEX
	 * deviceSubId = 4
	 * ============================================================
	 */
	private void setBioCaptureFingerprintForLeftIndex(
			boolean isUsedForAuthenication,
			String seedName) throws Exception {

		byte[] isoData = null;

		if (((SBIFingerSlapBioExceptionInfo)
				getCaptureInfo().getBioExceptionInfo())
				.getChkMissingLeftIndex() == SBICheckState.Unchecked) {

			isoData = getBiometricISOImage(
					seedName,
					SBIConstant.PROFILE_BIO_FILE_NAME_LEFT_INDEX);

			if (isoData != null &&
					!((SBIFingerSlapCaptureInfo)
							getCaptureInfo()).isCaptureLI()) {

				if (!isUsedForAuthenication) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setBioValueLI(
									StringHelper.base64UrlEncode(isoData));

				} else {

					getCaptureInfo().addBiometricForBioSubType(
							SBIConstant.BIO_NAME_LEFT_INDEX,
							StringHelper.base64UrlEncode(isoData));
				}

				if (isScoreFromIso()) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreLI(
									BioUtilHelper
											.getFingerQualityScoreFromIso(
													getPurpose(),
													isoData));

				} else {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreLI(getQualityScore());
				}

				((SBIFingerSlapCaptureInfo)
						getCaptureInfo())
						.setCaptureLI(true);
			}

		} else {

			((SBIFingerSlapCaptureInfo)
					getCaptureInfo())
					.setCaptureLI(true);
		}

		if (((SBIFingerSlapCaptureInfo)
				getCaptureInfo()).isCaptureLI()) {

			getCaptureInfo().setCaptureCompleted(true);
		}
	}

	/*
	 * ============================================================
	 * RIGHT INDEX
	 * deviceSubId = 5
	 * ============================================================
	 */
	private void setBioCaptureFingerprintForRightIndex(
			boolean isUsedForAuthenication,
			String seedName) throws Exception {

		byte[] isoData = null;

		if (((SBIFingerSlapBioExceptionInfo)
				getCaptureInfo().getBioExceptionInfo())
				.getChkMissingRightIndex() == SBICheckState.Unchecked) {

			isoData = getBiometricISOImage(
					seedName,
					SBIConstant.PROFILE_BIO_FILE_NAME_RIGHT_INDEX);

			if (isoData != null &&
					!((SBIFingerSlapCaptureInfo)
							getCaptureInfo()).isCaptureRI()) {

				if (!isUsedForAuthenication) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setBioValueRI(
									StringHelper.base64UrlEncode(isoData));

				} else {

					getCaptureInfo().addBiometricForBioSubType(
							SBIConstant.BIO_NAME_RIGHT_INDEX,
							StringHelper.base64UrlEncode(isoData));
				}

				if (isScoreFromIso()) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreRI(
									BioUtilHelper
											.getFingerQualityScoreFromIso(
													getPurpose(),
													isoData));

				} else {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreRI(getQualityScore());
				}

				((SBIFingerSlapCaptureInfo)
						getCaptureInfo())
						.setCaptureRI(true);
			}

		} else {

			((SBIFingerSlapCaptureInfo)
					getCaptureInfo())
					.setCaptureRI(true);
		}

		if (((SBIFingerSlapCaptureInfo)
				getCaptureInfo()).isCaptureRI()) {

			getCaptureInfo().setCaptureCompleted(true);
		}
	}

	/*
	 * ============================================================
	 * LEFT MIDDLE
	 * deviceSubId = 6
	 * ============================================================
	 */
	private void setBioCaptureFingerprintForLeftMiddle(
			boolean isUsedForAuthenication,
			String seedName) throws Exception {

		byte[] isoData = null;

		if (((SBIFingerSlapBioExceptionInfo)
				getCaptureInfo().getBioExceptionInfo())
				.getChkMissingLeftMiddle() == SBICheckState.Unchecked) {

			isoData = getBiometricISOImage(
					seedName,
					SBIConstant.PROFILE_BIO_FILE_NAME_LEFT_MIDDLE);

			if (isoData != null &&
					!((SBIFingerSlapCaptureInfo)
							getCaptureInfo()).isCaptureLM()) {

				if (!isUsedForAuthenication) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setBioValueLM(
									StringHelper.base64UrlEncode(isoData));

				} else {

					getCaptureInfo().addBiometricForBioSubType(
							SBIConstant.BIO_NAME_LEFT_MIDDLE,
							StringHelper.base64UrlEncode(isoData));
				}

				if (isScoreFromIso()) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreLM(
									BioUtilHelper
											.getFingerQualityScoreFromIso(
													getPurpose(),
													isoData));

				} else {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreLM(getQualityScore());
				}

				((SBIFingerSlapCaptureInfo)
						getCaptureInfo())
						.setCaptureLM(true);
			}

		} else {

			((SBIFingerSlapCaptureInfo)
					getCaptureInfo())
					.setCaptureLM(true);
		}

		if (((SBIFingerSlapCaptureInfo)
				getCaptureInfo()).isCaptureLM()) {

			getCaptureInfo().setCaptureCompleted(true);
		}
	}

	/*
	 * ============================================================
	 * RIGHT MIDDLE
	 * deviceSubId = 7
	 * ============================================================
	 */
	private void setBioCaptureFingerprintForRightMiddle(
			boolean isUsedForAuthenication,
			String seedName) throws Exception {

		byte[] isoData = null;

		if (((SBIFingerSlapBioExceptionInfo)
				getCaptureInfo().getBioExceptionInfo())
				.getChkMissingRightMiddle() == SBICheckState.Unchecked) {

			isoData = getBiometricISOImage(
					seedName,
					SBIConstant.PROFILE_BIO_FILE_NAME_RIGHT_MIDDLE);

			if (isoData != null &&
					!((SBIFingerSlapCaptureInfo)
							getCaptureInfo()).isCaptureRM()) {

				if (!isUsedForAuthenication) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setBioValueRM(
									StringHelper.base64UrlEncode(isoData));

				} else {

					getCaptureInfo().addBiometricForBioSubType(
							SBIConstant.BIO_NAME_RIGHT_MIDDLE,
							StringHelper.base64UrlEncode(isoData));
				}

				if (isScoreFromIso()) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreRM(
									BioUtilHelper
											.getFingerQualityScoreFromIso(
													getPurpose(),
													isoData));

				} else {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreRM(getQualityScore());
				}

				((SBIFingerSlapCaptureInfo)
						getCaptureInfo())
						.setCaptureRM(true);
			}

		} else {

			((SBIFingerSlapCaptureInfo)
					getCaptureInfo())
					.setCaptureRM(true);
		}

		if (((SBIFingerSlapCaptureInfo)
				getCaptureInfo()).isCaptureRM()) {

			getCaptureInfo().setCaptureCompleted(true);
		}
	}

	/*
	 * ============================================================
	 * LEFT RING
	 * deviceSubId = 8
	 * ============================================================
	 */
	private void setBioCaptureFingerprintForLeftRing(
			boolean isUsedForAuthenication,
			String seedName) throws Exception {

		byte[] isoData = null;

		if (((SBIFingerSlapBioExceptionInfo)
				getCaptureInfo().getBioExceptionInfo())
				.getChkMissingLeftRing() == SBICheckState.Unchecked) {

			isoData = getBiometricISOImage(
					seedName,
					SBIConstant.PROFILE_BIO_FILE_NAME_LEFT_RING);

			if (isoData != null &&
					!((SBIFingerSlapCaptureInfo)
							getCaptureInfo()).isCaptureLR()) {

				if (!isUsedForAuthenication) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setBioValueLR(
									StringHelper.base64UrlEncode(isoData));

				} else {

					getCaptureInfo().addBiometricForBioSubType(
							SBIConstant.BIO_NAME_LEFT_RING,
							StringHelper.base64UrlEncode(isoData));
				}

				if (isScoreFromIso()) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreLR(
									BioUtilHelper
											.getFingerQualityScoreFromIso(
													getPurpose(),
													isoData));

				} else {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreLR(getQualityScore());
				}

				((SBIFingerSlapCaptureInfo)
						getCaptureInfo())
						.setCaptureLR(true);
			}

		} else {

			((SBIFingerSlapCaptureInfo)
					getCaptureInfo())
					.setCaptureLR(true);
		}

		if (((SBIFingerSlapCaptureInfo)
				getCaptureInfo()).isCaptureLR()) {

			getCaptureInfo().setCaptureCompleted(true);
		}
	}

	/*
	 * ============================================================
	 * RIGHT RING
	 * deviceSubId = 9
	 * ============================================================
	 */
	private void setBioCaptureFingerprintForRightRing(
			boolean isUsedForAuthenication,
			String seedName) throws Exception {

		byte[] isoData = null;

		if (((SBIFingerSlapBioExceptionInfo)
				getCaptureInfo().getBioExceptionInfo())
				.getChkMissingRightRing() == SBICheckState.Unchecked) {

			isoData = getBiometricISOImage(
					seedName,
					SBIConstant.PROFILE_BIO_FILE_NAME_RIGHT_RING);

			if (isoData != null &&
					!((SBIFingerSlapCaptureInfo)
							getCaptureInfo()).isCaptureRR()) {

				if (!isUsedForAuthenication) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setBioValueRR(
									StringHelper.base64UrlEncode(isoData));

				} else {

					getCaptureInfo().addBiometricForBioSubType(
							SBIConstant.BIO_NAME_RIGHT_RING,
							StringHelper.base64UrlEncode(isoData));
				}

				if (isScoreFromIso()) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreRR(
									BioUtilHelper
											.getFingerQualityScoreFromIso(
													getPurpose(),
													isoData));

				} else {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreRR(getQualityScore());
				}

				((SBIFingerSlapCaptureInfo)
						getCaptureInfo())
						.setCaptureRR(true);
			}

		} else {

			((SBIFingerSlapCaptureInfo)
					getCaptureInfo())
					.setCaptureRR(true);
		}

		if (((SBIFingerSlapCaptureInfo)
				getCaptureInfo()).isCaptureRR()) {

			getCaptureInfo().setCaptureCompleted(true);
		}
	}

	/*
	 * ============================================================
	 * LEFT LITTLE
	 * deviceSubId = 10
	 * ============================================================
	 */
	private void setBioCaptureFingerprintForLeftLittle(
			boolean isUsedForAuthenication,
			String seedName) throws Exception {

		byte[] isoData = null;

		if (((SBIFingerSlapBioExceptionInfo)
				getCaptureInfo().getBioExceptionInfo())
				.getChkMissingLeftLittle() == SBICheckState.Unchecked) {

			isoData = getBiometricISOImage(
					seedName,
					SBIConstant.PROFILE_BIO_FILE_NAME_LEFT_LITTLE);

			if (isoData != null &&
					!((SBIFingerSlapCaptureInfo)
							getCaptureInfo()).isCaptureLL()) {

				if (!isUsedForAuthenication) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setBioValueLL(
									StringHelper.base64UrlEncode(isoData));

				} else {

					getCaptureInfo().addBiometricForBioSubType(
							SBIConstant.BIO_NAME_LEFT_LITTLE,
							StringHelper.base64UrlEncode(isoData));
				}

				if (isScoreFromIso()) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreLL(
									BioUtilHelper
											.getFingerQualityScoreFromIso(
													getPurpose(),
													isoData));

				} else {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreLL(getQualityScore());
				}

				((SBIFingerSlapCaptureInfo)
						getCaptureInfo())
						.setCaptureLL(true);
			}

		} else {

			((SBIFingerSlapCaptureInfo)
					getCaptureInfo())
					.setCaptureLL(true);
		}

		if (((SBIFingerSlapCaptureInfo)
				getCaptureInfo()).isCaptureLL()) {

			getCaptureInfo().setCaptureCompleted(true);
		}
	}

	/*
	 * ============================================================
	 * RIGHT LITTLE
	 * deviceSubId = 11
	 * ============================================================
	 */
	private void setBioCaptureFingerprintForRightLittle(
			boolean isUsedForAuthenication,
			String seedName) throws Exception {

		byte[] isoData = null;

		if (((SBIFingerSlapBioExceptionInfo)
				getCaptureInfo().getBioExceptionInfo())
				.getChkMissingRightLittle() == SBICheckState.Unchecked) {

			isoData = getBiometricISOImage(
					seedName,
					SBIConstant.PROFILE_BIO_FILE_NAME_RIGHT_LITTLE);

			if (isoData != null &&
					!((SBIFingerSlapCaptureInfo)
							getCaptureInfo()).isCaptureRL()) {

				if (!isUsedForAuthenication) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setBioValueRL(
									StringHelper.base64UrlEncode(isoData));

				} else {

					getCaptureInfo().addBiometricForBioSubType(
							SBIConstant.BIO_NAME_RIGHT_LITTLE,
							StringHelper.base64UrlEncode(isoData));
				}

				if (isScoreFromIso()) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreRL(
									BioUtilHelper
											.getFingerQualityScoreFromIso(
													getPurpose(),
													isoData));

				} else {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreRL(getQualityScore());
				}

				((SBIFingerSlapCaptureInfo)
						getCaptureInfo())
						.setCaptureRL(true);
			}

		} else {

			((SBIFingerSlapCaptureInfo)
					getCaptureInfo())
					.setCaptureRL(true);
		}

		if (((SBIFingerSlapCaptureInfo)
				getCaptureInfo()).isCaptureRL()) {

			getCaptureInfo().setCaptureCompleted(true);
		}
	}

	/*
	 * ============================================================
	 * LEFT THUMB
	 * deviceSubId = 12
	 * ============================================================
	 */
	private void setBioCaptureFingerprintForLeftThumb(
			boolean isUsedForAuthenication,
			String seedName) throws Exception {

		byte[] isoData = null;

		if (((SBIFingerSlapBioExceptionInfo)
				getCaptureInfo().getBioExceptionInfo())
				.getChkMissingLeftThumb() == SBICheckState.Unchecked) {

			isoData = getBiometricISOImage(
					seedName,
					SBIConstant.PROFILE_BIO_FILE_NAME_LEFT_THUMB);

			if (isoData != null &&
					!((SBIFingerSlapCaptureInfo)
							getCaptureInfo()).isCaptureLT()) {

				if (!isUsedForAuthenication) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setBioValueLT(
									StringHelper.base64UrlEncode(isoData));

				} else {

					getCaptureInfo().addBiometricForBioSubType(
							SBIConstant.BIO_NAME_LEFT_THUMB,
							StringHelper.base64UrlEncode(isoData));
				}

				if (isScoreFromIso()) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreLT(
									BioUtilHelper
											.getFingerQualityScoreFromIso(
													getPurpose(),
													isoData));

				} else {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreLT(getQualityScore());
				}

				((SBIFingerSlapCaptureInfo)
						getCaptureInfo())
						.setCaptureLT(true);
			}

		} else {

			((SBIFingerSlapCaptureInfo)
					getCaptureInfo())
					.setCaptureLT(true);
		}

		if (((SBIFingerSlapCaptureInfo)
				getCaptureInfo()).isCaptureLT()) {

			getCaptureInfo().setCaptureCompleted(true);
		}
	}

	/*
	 * ============================================================
	 * RIGHT THUMB
	 * deviceSubId = 13
	 * ============================================================
	 */
	private void setBioCaptureFingerprintForRightThumb(
			boolean isUsedForAuthenication,
			String seedName) throws Exception {

		byte[] isoData = null;

		if (((SBIFingerSlapBioExceptionInfo)
				getCaptureInfo().getBioExceptionInfo())
				.getChkMissingRightThumb() == SBICheckState.Unchecked) {

			isoData = getBiometricISOImage(
					seedName,
					SBIConstant.PROFILE_BIO_FILE_NAME_RIGHT_THUMB);

			if (isoData != null &&
					!((SBIFingerSlapCaptureInfo)
							getCaptureInfo()).isCaptureRT()) {

				if (!isUsedForAuthenication) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setBioValueRT(
									StringHelper.base64UrlEncode(isoData));

				} else {

					getCaptureInfo().addBiometricForBioSubType(
							SBIConstant.BIO_NAME_RIGHT_THUMB,
							StringHelper.base64UrlEncode(isoData));
				}

				if (isScoreFromIso()) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreRT(
									BioUtilHelper
											.getFingerQualityScoreFromIso(
													getPurpose(),
													isoData));

				} else {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreRT(getQualityScore());
				}

				((SBIFingerSlapCaptureInfo)
						getCaptureInfo())
						.setCaptureRT(true);
			}

		} else {

			((SBIFingerSlapCaptureInfo)
					getCaptureInfo())
					.setCaptureRT(true);
		}

		if (((SBIFingerSlapCaptureInfo)
				getCaptureInfo()).isCaptureRT()) {

			getCaptureInfo().setCaptureCompleted(true);
		}
	}

	/*
	 * ============================================================
	 * TWO THUMBS
	 * deviceSubId = 3
	 * ============================================================
	 */
	private void setBioCaptureFingerprintForSubTypeThumb(
			boolean isUsedForAuthenication,
			String seedName) throws Exception {

		byte[] isoData = null;

		/*
		 * LEFT THUMB
		 */
		if (((SBIFingerSlapBioExceptionInfo)
				getCaptureInfo().getBioExceptionInfo())
				.getChkMissingLeftThumb() == SBICheckState.Unchecked) {

			isoData = getBiometricISOImage(
					seedName,
					SBIConstant.PROFILE_BIO_FILE_NAME_LEFT_THUMB);

			if (isoData != null &&
					!((SBIFingerSlapCaptureInfo)
							getCaptureInfo()).isCaptureLT()) {

				if (!isUsedForAuthenication) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setBioValueLT(
									StringHelper.base64UrlEncode(isoData));

				} else {

					getCaptureInfo().addBiometricForBioSubType(
							SBIConstant.BIO_NAME_LEFT_THUMB,
							StringHelper.base64UrlEncode(isoData));
				}

				if (isScoreFromIso()) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreLT(
									BioUtilHelper
											.getFingerQualityScoreFromIso(
													getPurpose(),
													isoData));

				} else {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreLT(getQualityScore());
				}

				((SBIFingerSlapCaptureInfo)
						getCaptureInfo())
						.setCaptureLT(true);
			}

		} else {

			((SBIFingerSlapCaptureInfo)
					getCaptureInfo())
					.setCaptureLT(true);
		}

		/*
		 * RIGHT THUMB
		 */
		if (((SBIFingerSlapBioExceptionInfo)
				getCaptureInfo().getBioExceptionInfo())
				.getChkMissingRightThumb() == SBICheckState.Unchecked) {

			isoData = getBiometricISOImage(
					seedName,
					SBIConstant.PROFILE_BIO_FILE_NAME_RIGHT_THUMB);

			if (isoData != null &&
					!((SBIFingerSlapCaptureInfo)
							getCaptureInfo()).isCaptureRT()) {

				if (!isUsedForAuthenication) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setBioValueRT(
									StringHelper.base64UrlEncode(isoData));

				} else {

					getCaptureInfo().addBiometricForBioSubType(
							SBIConstant.BIO_NAME_RIGHT_THUMB,
							StringHelper.base64UrlEncode(isoData));
				}

				if (isScoreFromIso()) {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreRT(
									BioUtilHelper
											.getFingerQualityScoreFromIso(
													getPurpose(),
													isoData));

				} else {

					((SBIFingerSlapCaptureInfo)
							getCaptureInfo())
							.setCaptureScoreRT(getQualityScore());
				}

				((SBIFingerSlapCaptureInfo)
						getCaptureInfo())
						.setCaptureRT(true);
			}

		} else {

			((SBIFingerSlapCaptureInfo)
					getCaptureInfo())
					.setCaptureRT(true);
		}

		/*
		 * Complete when either thumb is captured.
		 * This preserves the behavior of your existing code.
		 */
		if (((SBIFingerSlapCaptureInfo)
				getCaptureInfo()).isCaptureLT()
				||
				((SBIFingerSlapCaptureInfo)
						getCaptureInfo()).isCaptureRT()) {

			getCaptureInfo().setCaptureCompleted(true);
		}
	}

	/*
	 * ============================================================
	 * RIGHT SLAP
	 * deviceSubId = 2
	 *
	 * Captures:
	 * RI + RM + RR + RL
	 * ============================================================
	 */
	private void setBioCaptureFingerprintForSubTypeRight(
			boolean isUsedForAuthenication,
			String seedName) throws Exception {

		setBioCaptureFingerprintForRightIndex(
				isUsedForAuthenication,
				seedName);

		setBioCaptureFingerprintForRightMiddle(
				isUsedForAuthenication,
				seedName);

		setBioCaptureFingerprintForRightRing(
				isUsedForAuthenication,
				seedName);

		setBioCaptureFingerprintForRightLittle(
				isUsedForAuthenication,
				seedName);
	}

	/*
	 * ============================================================
	 * LEFT SLAP
	 * deviceSubId = 1
	 *
	 * Captures:
	 * LI + LM + LR + LL
	 * ============================================================
	 */
	private void setBioCaptureFingerprintForSubTypeLeft(
			boolean isUsedForAuthenication,
			String seedName) throws Exception {

		setBioCaptureFingerprintForLeftIndex(
				isUsedForAuthenication,
				seedName);

		setBioCaptureFingerprintForLeftMiddle(
				isUsedForAuthenication,
				seedName);

		setBioCaptureFingerprintForLeftRing(
				isUsedForAuthenication,
				seedName);

		setBioCaptureFingerprintForLeftLittle(
				isUsedForAuthenication,
				seedName);
	}
}