package io.mosip.mock.sbi.service;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Semaphore;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.biometric.provider.CryptoUtility;
import org.biometric.provider.JwtUtility;
import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.SerializationConfig;
import org.codehaus.jackson.map.annotate.JsonSerialize.Inclusion;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.squareup.okhttp.MediaType;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.RequestBody;
import com.squareup.okhttp.Response;

import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.mock.sbi.SBIConstant;
import io.mosip.mock.sbi.devicehelper.SBIBioSubTypeInfo;
import io.mosip.mock.sbi.devicehelper.SBICheckState;
import io.mosip.mock.sbi.devicehelper.SBIDeviceHelper;
import io.mosip.mock.sbi.devicehelper.face.SBIFaceCaptureInfo;
import io.mosip.mock.sbi.devicehelper.face.SBIFaceHelper;
import io.mosip.mock.sbi.devicehelper.finger.single.SBIFingerSingleCaptureInfo;
import io.mosip.mock.sbi.devicehelper.finger.single.SBIFingerSingleHelper;
import io.mosip.mock.sbi.devicehelper.finger.slap.SBIFingerSlapBioExceptionInfo;
import io.mosip.mock.sbi.devicehelper.finger.slap.SBIFingerSlapCaptureInfo;
import io.mosip.mock.sbi.devicehelper.finger.slap.SBIFingerSlapHelper;
import io.mosip.mock.sbi.devicehelper.iris.binacular.SBIIrisDoubleBioExceptionInfo;
import io.mosip.mock.sbi.devicehelper.iris.binacular.SBIIrisDoubleCaptureInfo;
import io.mosip.mock.sbi.devicehelper.iris.binacular.SBIIrisDoubleHelper;
import io.mosip.mock.sbi.devicehelper.iris.monocular.SBIIrisSingleBioExceptionInfo;
import io.mosip.mock.sbi.devicehelper.iris.monocular.SBIIrisSingleCaptureInfo;
import io.mosip.mock.sbi.devicehelper.iris.monocular.SBIIrisSingleHelper;
import io.mosip.mock.sbi.exception.SBIException;
import io.mosip.mock.sbi.util.ApplicationPropertyHelper;
import io.mosip.mock.sbi.util.StringHelper;
import io.mosip.registration.mdm.dto.BioMetricsDataDto;
import io.mosip.registration.mdm.dto.BioMetricsDto;
import io.mosip.registration.mdm.dto.CaptureRequestDeviceDetailDto;
import io.mosip.registration.mdm.dto.CaptureRequestDto;
import io.mosip.registration.mdm.dto.DelayRequest;
import io.mosip.registration.mdm.dto.DeviceDiscoveryRequestDetail;
import io.mosip.registration.mdm.dto.DeviceInfo;
import io.mosip.registration.mdm.dto.DeviceInfoDto;
import io.mosip.registration.mdm.dto.DiscoverDto;
import io.mosip.registration.mdm.dto.ErrorInfo;
import io.mosip.registration.mdm.dto.ProfileRequest;
import io.mosip.registration.mdm.dto.RCaptureResponse;
import io.mosip.registration.mdm.dto.ScoreRequest;
import io.mosip.registration.mdm.dto.StatusRequest;
import io.mosip.registration.mdm.dto.StreamingRequestDetail;

public class SBIServiceResponse {

	private static final Logger LOGGER = LoggerFactory.getLogger(SBIServiceResponse.class);
	private static String AUTH_REQ_TEMPLATE = "{ \"id\": \"string\",\"metadata\": {},\"request\": { \"appId\": \"%s\", \"clientId\": \"%s\", \"secretKey\": \"%s\" }, \"requesttime\": \"%s\", \"version\": \"string\"}";

	protected int port = 0;
	protected String request = "";
	static Semaphore semaphore = new Semaphore(1);

	private String[] bioExceptionsArrayFinger = {"Left IndexFinger", "Left MiddleFinger", "Left RingFinger", "Left LittleFinger", "Left Thumb", "Right IndexFinger", "Right MiddleFinger", "Right RingFinger", "Right LittleFinger", "Right Thumb"};
	private String[] bioExceptionsArrayIris = {"Left", "Right"};
	private List<String> bioExceptionsListFinger = Arrays.asList(bioExceptionsArrayFinger);
	private List<String> bioExceptionsListIris = Arrays.asList(bioExceptionsArrayIris);

	private String[] bioSubtypesArrayFinger = {"Left IndexFinger", "Left MiddleFinger", "Left RingFinger", "Left LittleFinger", "Left Thumb", "Right IndexFinger", "Right MiddleFinger", "Right RingFinger", "Right LittleFinger", "Right Thumb", "UNKNOWN"};
	private String[] bioSubtypesArrayIris = {"Left", "Right", "UNKNOWN"};
	private List<String> bioSubtypesListFinger = Arrays.asList(bioSubtypesArrayFinger);
	private List<String> bioSubtypesListIris = Arrays.asList(bioSubtypesArrayIris);

	public SBIServiceResponse(int port) {
		setPort(port);
	}

	public String getServiceresponse(SBIMockService mockService, Socket socket, String strJsonRequest) {
		String responseJson = "";
		setRequest(strJsonRequest);

		if (strJsonRequest.contains(SBIConstant.MOSIP_POST_VERB) ||
				strJsonRequest.contains(SBIConstant.MOSIP_GET_VERB) ||
				strJsonRequest.contains(SBIConstant.MOSIP_DISC_VERB)) {
			responseJson = processDeviceDicoveryInfo(mockService);
		} else if (strJsonRequest.contains(SBIConstant.MOSIP_INFO_VERB)) {
			responseJson = processDeviceInfo(mockService);
		} else if (strJsonRequest.contains(SBIConstant.MOSIP_STREAM_VERB)) {
			responseJson = processLiveStreamInfo(mockService, socket);
		} else if (strJsonRequest.contains(SBIConstant.MOSIP_RCAPTURE_VERB)) {
			responseJson = processRCaptureInfo(mockService);
		} else if (strJsonRequest.contains(SBIConstant.MOSIP_CAPTURE_VERB)) {
			responseJson = processCaptureInfo(mockService);
		} else if (strJsonRequest.contains(SBIConstant.MOSIP_ADMIN_API_STATUS)) {
			responseJson = processSetStatus(mockService);
		} else if (strJsonRequest.contains(SBIConstant.MOSIP_ADMIN_API_SCORE)) {
			responseJson = processSetQualityScore(mockService);
		} else if (strJsonRequest.contains(SBIConstant.MOSIP_ADMIN_API_DELAY)) {
			responseJson = processSetDelay(mockService);
		} else if (strJsonRequest.contains(SBIConstant.MOSIP_ADMIN_API_PROFILE)) {
			responseJson = processSetProfileInfo(mockService);
		} else {
			responseJson = SBIResponseInfo.generateErrorResponse("en", getPort(), "500", "");
		}
		return responseJson;
	}

	public String processDeviceDicoveryInfo(SBIMockService mockService) {
		String response = null;
		String lang = "en";
		try {
			ObjectMapper objectMapper = new ObjectMapper();
			DeviceDiscoveryRequestDetail requestObject = (DeviceDiscoveryRequestDetail) getRequestJson(SBIConstant.MOSIP_DISC_VERB);
			String type = null;
			if (requestObject != null && requestObject.getType() != null && requestObject.getType().length() > 0)
				type = requestObject.getType();

			LOGGER.info("processDeviceDicoveryInfo :: type :: " + type);

			List<DiscoverDto> infoList = new ArrayList<DiscoverDto>();
			if (type == null || type.trim().length() == 0) {
				return SBIJsonInfo.getErrorJson(lang, "502", "");
			} else if (!type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE)
					&& !type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER)
					&& !type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE)
					&& !type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS)) {
				return SBIJsonInfo.getErrorJson(lang, "502", "");
			} else {
				long delay = 0;
				SBIDeviceHelper deviceHelper = null;
				if (type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE)
						|| type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER)) {
					switch (mockService.getPurpose()) {
						case SBIConstant.PURPOSE_REGISTRATION:
							deviceHelper = (SBIFingerSlapHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP);
							break;
						case SBIConstant.PURPOSE_AUTH:
							deviceHelper = (SBIFingerSingleHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SINGLE);
							break;
					}
					if (deviceHelper != null) {
						delay = deviceHelper.getDelayForMethod(SBIConstant.MOSIP_METHOD_MOSIPDISC);
						delay(delay);

						deviceHelper.initDeviceDetails();
						DiscoverDto discoverInfo = deviceHelper.getDiscoverDto();
						if (discoverInfo != null)
							infoList.add(discoverInfo);
					}
				}

				if (type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE)
						|| type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE)) {
					deviceHelper = (SBIFaceHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE);
					if (deviceHelper != null) {
						delay = deviceHelper.getDelayForMethod(SBIConstant.MOSIP_METHOD_MOSIPDISC);
						delay(delay);
						deviceHelper.initDeviceDetails();
						DiscoverDto discoverInfo = deviceHelper.getDiscoverDto();
						if (discoverInfo != null)
							infoList.add(discoverInfo);
					}
				}

				if (type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE)
						|| type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS)) {
					switch (mockService.getPurpose()) {
						case SBIConstant.PURPOSE_REGISTRATION:
							deviceHelper = (SBIIrisDoubleHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_DOUBLE);
							break;
						case SBIConstant.PURPOSE_AUTH:
							deviceHelper = (SBIIrisSingleHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_SINGLE);
							break;
					}
					if (deviceHelper != null) {
						delay = deviceHelper.getDelayForMethod(SBIConstant.MOSIP_METHOD_MOSIPDISC);
						delay(delay);

						deviceHelper.initDeviceDetails();
						DiscoverDto discoverInfo = deviceHelper.getDiscoverDto();
						if (discoverInfo != null)
							infoList.add(discoverInfo);
					}
				}

				if (infoList != null && infoList.size() > 0) {
					return objectMapper.writeValueAsString(infoList);
				} else {
					return SBIJsonInfo.getErrorJson(lang, "503", "");
				}
			}
		} catch (Exception ex) {
			response = SBIResponseInfo.generateErrorResponse(lang, getPort(), SBIConstant.Error_Code_999 + "", "");
			LOGGER.error("processDeviceDicoveryInfo", ex);
		} finally {
		}
		return response;
	}

	public String processDeviceInfo(SBIMockService mockService) {
		String response = null;
		String lang = "en";
		try {
			long delay = 0;
			ObjectMapper objectMapper = new ObjectMapper();

			List<DeviceInfoDto> infoList = new ArrayList<DeviceInfoDto>();
			DeviceInfoDto deviceInfoDto = null;
			SBIDeviceHelper deviceHelper = null;
			switch (mockService.getPurpose()) {
				case SBIConstant.PURPOSE_REGISTRATION:
					deviceHelper = (SBIFingerSlapHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP);
					break;
				case SBIConstant.PURPOSE_AUTH:
					deviceHelper = (SBIFingerSingleHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SINGLE);
					break;
			}

			if (deviceHelper != null) {
				delay = deviceHelper.getDelayForMethod(SBIConstant.MOSIP_METHOD_MOSIPDINFO);
				delay(delay);

				deviceHelper.initDeviceDetails();
				deviceInfoDto = deviceHelper.getDeviceInfoDto();
				if (deviceInfoDto != null)
					infoList.add(deviceInfoDto);
			}

			deviceHelper = (SBIFaceHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE);
			if (deviceHelper != null) {
				delay = deviceHelper.getDelayForMethod(SBIConstant.MOSIP_METHOD_MOSIPDINFO);
				delay(delay);

				deviceHelper.initDeviceDetails();
				deviceInfoDto = deviceHelper.getDeviceInfoDto();
				if (deviceInfoDto != null)
					infoList.add(deviceInfoDto);
			}

			switch (mockService.getPurpose()) {
				case SBIConstant.PURPOSE_REGISTRATION:
					deviceHelper = (SBIIrisDoubleHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_DOUBLE);
					break;
				case SBIConstant.PURPOSE_AUTH:
					deviceHelper = (SBIIrisSingleHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_SINGLE);
					break;
			}
			if (deviceHelper != null) {
				delay = deviceHelper.getDelayForMethod(SBIConstant.MOSIP_METHOD_MOSIPDINFO);
				delay(delay);

				deviceHelper.initDeviceDetails();
				deviceInfoDto = deviceHelper.getDeviceInfoDto();
				if (deviceInfoDto != null)
					infoList.add(deviceInfoDto);
			}

			if (infoList != null && infoList.size() > 0) {
				return objectMapper.writeValueAsString(infoList);
			} else {
				return SBIJsonInfo.getErrorJson(lang, "106", "");
			}
		} catch (Exception ex) {
			response = SBIResponseInfo.generateErrorResponse(lang, getPort(), SBIConstant.Error_Code_999 + "", "");
			LOGGER.error("processDeviceDicoveryInfo", ex);
		} finally {
		}
		return response;
	}

	public String processSetStatus(SBIMockService mockService) {
		String response = null;
		String lang = "en";
		try {
			StatusRequest requestObject = (StatusRequest) getRequestJson(SBIConstant.MOSIP_ADMIN_API_STATUS);
			String type = null, status = null;
			if (requestObject != null && requestObject.getType() != null && requestObject.getType().length() > 0)
				type = requestObject.getType();

			if (requestObject != null && requestObject.getDeviceStatus() != null && requestObject.getDeviceStatus().length() > 0)
				status = requestObject.getDeviceStatus();

			LOGGER.info("processSetStatus :: Type :: " + type + " :: Status :: " + status);

			if (type == null || type.trim().length() == 0) {
				return SBIJsonInfo.getAdminApiErrorJson(lang, "502", "");
			} else if (!type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE)
					&& !type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER)
					&& !type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE)
					&& !type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS)) {
				return SBIJsonInfo.getAdminApiErrorJson(lang, "502", "");
			} else if (!status.equals(SBIConstant.DEVICE_STATUS_ISREADY)
					&& !status.equals(SBIConstant.DEVICE_STATUS_ISBUSY)
					&& !status.equals(SBIConstant.DEVICE_STATUS_NOTREADY)
					&& !status.equals(SBIConstant.DEVICE_STATUS_NOTREGISTERED)) {
				return SBIJsonInfo.getAdminApiErrorJson(lang, "504", "");
			} else {
				SBIDeviceHelper deviceHelper = null;
				switch (mockService.getPurpose()) {
					case SBIConstant.PURPOSE_REGISTRATION:
						deviceHelper = (SBIFingerSlapHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP);
						break;
					case SBIConstant.PURPOSE_AUTH:
						deviceHelper = (SBIFingerSingleHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SINGLE);
						break;
				}
				if (deviceHelper != null) {
					deviceHelper.setDeviceStatus((type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE) || type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER) ? status : SBIConstant.DEVICE_STATUS_ISREADY));
				}

				deviceHelper = (SBIFaceHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE);
				if (deviceHelper != null) {
					deviceHelper.setDeviceStatus((type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE) || type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE) ? status : SBIConstant.DEVICE_STATUS_ISREADY));
				}

				switch (mockService.getPurpose()) {
					case SBIConstant.PURPOSE_REGISTRATION:
						deviceHelper = (SBIIrisDoubleHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_DOUBLE);
						break;
					case SBIConstant.PURPOSE_AUTH:
						deviceHelper = (SBIIrisSingleHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_SINGLE);
						break;
				}
				if (deviceHelper != null) {
					deviceHelper.setDeviceStatus((type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE) || type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS) ? status : SBIConstant.DEVICE_STATUS_ISREADY));
				}
			}

			response = SBIJsonInfo.getAdminApiErrorJson(lang, "0", "");
		} catch (Exception ex) {
			response = SBIJsonInfo.getAdminApiErrorJson(lang, "999", ex.getLocalizedMessage() + "");
			LOGGER.error("processSetStatus", ex);
		} finally {
		}
		return response;
	}

	public String processSetQualityScore(SBIMockService mockService) {
		String response = null;
		String lang = "en";
		try {
			ScoreRequest requestObject = (ScoreRequest) getRequestJson(SBIConstant.MOSIP_ADMIN_API_SCORE);
			String type = null, qualityScore = null;
			boolean scoreFromIso = false;
			if (requestObject != null && requestObject.getType() != null && requestObject.getType().length() > 0)
				type = requestObject.getType();

			if (requestObject != null && requestObject.getQualityScore() != null && requestObject.getQualityScore().length() > 0)
				qualityScore = requestObject.getQualityScore();

			if (requestObject != null)
				scoreFromIso = requestObject.isFromIso();

			LOGGER.info("processSetQualityScore :: Type :: " + type + " :: qualityScore :: " + qualityScore + " :: fromIso :: " + scoreFromIso);

			if (type == null || type.trim().length() == 0) {
				response = SBIJsonInfo.getAdminApiErrorJson(lang, "502", "");
			} else if (!type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE)
					&& !type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER)
					&& !type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE)
					&& !type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS)) {
				response = SBIJsonInfo.getAdminApiErrorJson(lang, "502", "");
			} else if (qualityScore == null || qualityScore.trim().length() == 0) {
				response = SBIJsonInfo.getAdminApiErrorJson(lang, "505", "");
			} else if (qualityScore != null && (Integer.parseInt(qualityScore) < 0 || Integer.parseInt(qualityScore) > 100)) {
				response = SBIJsonInfo.getAdminApiErrorJson(lang, "505", "");
			} else {
				int defaultQualityScore = Integer.parseInt(ApplicationPropertyHelper.getPropertyKeyValue(SBIConstant.MOSIP_MOCK_SBI_QUALITY_SCORE));

				SBIDeviceHelper deviceHelper = null;
				switch (mockService.getPurpose()) {
					case SBIConstant.PURPOSE_REGISTRATION:
						deviceHelper = (SBIFingerSlapHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP);
						break;
					case SBIConstant.PURPOSE_AUTH:
						deviceHelper = (SBIFingerSingleHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SINGLE);
						break;
				}
				if (deviceHelper != null) {
					deviceHelper.setScoreFromIso((type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE) || type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER)) ? scoreFromIso : false);
					deviceHelper.setQualityScore((type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE) || type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER)) ? Integer.parseInt(qualityScore) : defaultQualityScore);
					deviceHelper.setQualityScoreSet((type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE) || type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER)) ? true : false);
				}

				deviceHelper = (SBIFaceHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE);
				if (deviceHelper != null) {
					deviceHelper.setScoreFromIso((type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE) || type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE)) ? scoreFromIso : false);
					deviceHelper.setQualityScore((type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE) || type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE)) ? Integer.parseInt(qualityScore) : defaultQualityScore);
					deviceHelper.setQualityScoreSet((type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE) || type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE)) ? true : false);
				}

				switch (mockService.getPurpose()) {
					case SBIConstant.PURPOSE_REGISTRATION:
						deviceHelper = (SBIIrisDoubleHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_DOUBLE);
						break;
					case SBIConstant.PURPOSE_AUTH:
						deviceHelper = (SBIIrisSingleHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_SINGLE);
						break;
				}
				if (deviceHelper != null) {
					deviceHelper.setScoreFromIso((type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE) || type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS)) ? scoreFromIso : false);
					deviceHelper.setQualityScore((type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE) || type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS)) ? Integer.parseInt(qualityScore) : defaultQualityScore);
					deviceHelper.setQualityScoreSet((type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE) || type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS)) ? true : false);
				}

				response = SBIJsonInfo.getAdminApiErrorJson(lang, "0", "");
			}
		} catch (Exception ex) {
			response = SBIJsonInfo.getAdminApiErrorJson(lang, "999", ex.getLocalizedMessage() + "");
			LOGGER.error("processSetQualityScore", ex);
		} finally {
		}
		return response;
	}

	public String processSetDelay(SBIMockService mockService) {
		String response = null;
		String lang = "en";
		try {
			DelayRequest requestObject = (DelayRequest) getRequestJson(SBIConstant.MOSIP_ADMIN_API_DELAY);
			String type = null, delay = null, method[] = null;
			if (requestObject != null && requestObject.getType() != null && requestObject.getType().length() > 0)
				type = requestObject.getType();

			if (requestObject != null && requestObject.getDelay() != null && requestObject.getDelay().length() > 0)
				delay = requestObject.getDelay();

			if (requestObject != null && requestObject.getMethod() != null && requestObject.getMethod().length > 0)
				method = requestObject.getMethod();

			LOGGER.info("processSetDelay :: Type :: " + type + " :: Delay :: " + delay);

			if (type == null || type.trim().length() == 0) {
				response = SBIJsonInfo.getAdminApiErrorJson(lang, "502", "");
			} else if (!type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE)
					&& !type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER)
					&& !type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE)
					&& !type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS)) {
				response = SBIJsonInfo.getAdminApiErrorJson(lang, "502", "");
			} else if (delay == null || delay.trim().length() == 0) {
				response = SBIJsonInfo.getAdminApiErrorJson(lang, "506", "");
			} else if (delay != null && Long.parseLong(delay) < 0) {
				response = SBIJsonInfo.getAdminApiErrorJson(lang, "506", "");
			} else {
				boolean isValidMethod = true;
				String corsHeaderMethodsFor = ApplicationPropertyHelper.getPropertyKeyValue(SBIConstant.CORS_HEADER_METHODS);
				if (method == null || method.length == 0) {
					method = corsHeaderMethodsFor.split(",");
				}
				if (method != null || method.length > 0) {
					for (int index = 0; index < method.length; index++) {
						if (!corsHeaderMethodsFor.contains(method[index].trim())) {
							response = SBIJsonInfo.getAdminApiErrorJson(lang, "507", "");
							isValidMethod = false;
							break;
						}
					}
				}
				if (isValidMethod) {
					SBIDeviceHelper deviceHelper = null;
					switch (mockService.getPurpose()) {
						case SBIConstant.PURPOSE_REGISTRATION:
							deviceHelper = (SBIFingerSlapHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP);
							break;
						case SBIConstant.PURPOSE_AUTH:
							deviceHelper = (SBIFingerSingleHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SINGLE);
							break;
					}

					if (deviceHelper != null) {
						deviceHelper.resetDelayForMethod();
						deviceHelper.setDelayForMethod((type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE) || type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER)) ? method : null, Long.parseLong(delay));
					}

					deviceHelper = (SBIFaceHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE);
					if (deviceHelper != null) {
						deviceHelper.resetDelayForMethod();
						deviceHelper.setDelayForMethod((type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE) || type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE)) ? method : null, Long.parseLong(delay));
					}

					switch (mockService.getPurpose()) {
						case SBIConstant.PURPOSE_REGISTRATION:
							deviceHelper = (SBIIrisDoubleHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_DOUBLE);
							break;
						case SBIConstant.PURPOSE_AUTH:
							deviceHelper = (SBIIrisSingleHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_SINGLE);
							break;
					}
					if (deviceHelper != null) {
						deviceHelper.resetDelayForMethod();
						deviceHelper.setDelayForMethod((type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_BIOMETRIC_DEVICE) || type.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS)) ? method : null, Long.parseLong(delay));
					}

					response = SBIJsonInfo.getAdminApiErrorJson(lang, "0", "");
				}
			}
		} catch (Exception ex) {
			response = SBIJsonInfo.getAdminApiErrorJson(lang, "999", ex.getLocalizedMessage() + "");
			LOGGER.error("processSetDelay", ex);
		} finally {
		}
		return response;
	}

	public String processSetProfileInfo(SBIMockService mockService) {
		String response = null;
		String lang = "en";
		try {
			ProfileRequest requestObject = (ProfileRequest) getRequestJson(SBIConstant.MOSIP_ADMIN_API_PROFILE);
			if (requestObject != null && requestObject.getProfileId() != null && requestObject.getProfileId().length() > 0) {
				mockService.setProfileId(requestObject.getProfileId());
				response = SBIJsonInfo.getAdminApiErrorJson(lang, "0", "");
			} else {
				LOGGER.info("processSetProfileInfo :: ProfileId :: Was  Not SET Check the JSON request :: ");
				mockService.setProfileId(SBIConstant.PROFILE_DEFAULT);
				response = SBIJsonInfo.getAdminApiErrorJson(lang, "0", "");
			}

			LOGGER.info("processSetProfileInfo :: ProfileId :: " + mockService.getProfileId());
		} catch (Exception ex) {
			response = SBIJsonInfo.getAdminApiErrorJson(lang, "999", ex.getLocalizedMessage() + "");
			LOGGER.error("processSetProfileInfo", ex);
		} finally {
		}
		return response;
	}

	private String processLiveStreamInfo(SBIMockService mockService, Socket socket) {
		String response = null;
		String lang = "en";
		SBIDeviceHelper deviceHelper = null;
		try {
			if (mockService.getPurpose().equals(ApplicationPropertyHelper.getPropertyKeyValue(SBIConstant.MOSIP_PURPOSE_AUTH))) {
				return SBIJsonInfo.getStreamErrorJson(lang, "601", "");
			}

			StreamingRequestDetail requestObject = (StreamingRequestDetail) getRequestJson(SBIConstant.MOSIP_STREAM_VERB);
			String deviceId = requestObject.getDeviceId();
			int deviceSubId = Integer.parseInt(requestObject.getDeviceSubId());
			boolean isStreamTimeoutSet = false;
			long timeout = 0;
			if (requestObject.getTimeout() != null && requestObject.getTimeout().trim().length() != 0 && Long.parseLong(requestObject.getTimeout().trim()) > 0) {
				timeout = Long.parseLong(requestObject.getTimeout().trim());
				isStreamTimeoutSet = true;
			}

			LOGGER.info("processLiveStreamInfo :: deviceId :: " + deviceId + " :: deviceSubId ::" + deviceSubId);

			if (deviceId != null && deviceId.trim().length() == 0) {
				return SBIJsonInfo.getStreamErrorJson(lang, "604", "");
			}

			deviceHelper = getDeviceHelperForDeviceId(mockService, deviceId);
			if (deviceHelper == null || deviceHelper.getDeviceInfo() == null) {
				return SBIJsonInfo.getStreamErrorJson(lang, "605", "");
			}
			if (deviceHelper.getDeviceInfo() != null && !deviceHelper.getDeviceInfo().getPurpose().equals(SBIConstant.PURPOSE_REGISTRATION)) {
				return SBIJsonInfo.getStreamErrorJson(lang, "606", "");
			}
			if (deviceHelper.getDeviceInfo() != null && deviceHelper.getDeviceInfo().getDeviceStatus().equals(SBIConstant.DEVICE_STATUS_NOTREGISTERED)) {
				return SBIJsonInfo.getStreamErrorJson(lang, "100", "");
			}
			if (deviceHelper.getDeviceInfo() != null && deviceHelper.getDeviceInfo().getDeviceStatus().equals(SBIConstant.DEVICE_STATUS_NOTREADY)) {
				return SBIJsonInfo.getStreamErrorJson(lang, "110", "");
			}
			if (deviceHelper.getDeviceInfo() != null && deviceHelper.getDeviceInfo().getDeviceStatus().equals(SBIConstant.DEVICE_STATUS_ISBUSY)) {
				return SBIJsonInfo.getStreamErrorJson(lang, "111", "");
			}
			if (deviceHelper.getDeviceInfo() != null && !deviceHelper.getDeviceInfo().getDeviceStatus().equals(SBIConstant.DEVICE_STATUS_ISREADY)) {
				return SBIJsonInfo.getStreamErrorJson(lang, "607", "");
			}

			deviceHelper.setDeviceStatus(SBIConstant.DEVICE_STATUS_ISBUSY);
			deviceHelper.initDevice();
			deviceHelper.setDeviceId(deviceId);
			deviceHelper.setDeviceSubId(deviceSubId);
			deviceHelper.getCaptureInfo().setLiveStreamStarted(true);
			renderMainHeaderData(socket);
			int returnCode = -1;

			long startTime = System.currentTimeMillis();
			long endTime = startTime + timeout;
			boolean streamTimeOut = false;

			long delay = deviceHelper.getDelayForMethod(SBIConstant.MOSIP_METHOD_STREAM);
			while (true) {
				delay(delay);
				if (isStreamTimeoutSet && System.currentTimeMillis() > endTime) {
					streamTimeOut = true;
					break;
				}

				if (deviceHelper.getCaptureInfo() == null) {
					response = "ok";
					break;
				}

				try {
					// acquiring the lock
					if (semaphore != null)
						semaphore.acquire();

					returnCode = deviceHelper.getLiveStream();

					if (returnCode < 0)
						break;
					if (returnCode != 0)
						continue;
				} catch (Exception ex) {
				} finally {
					try {
						if (semaphore != null)
							semaphore.release();
					} catch (Exception ex) {
					}
				}

				if (deviceHelper.getCaptureInfo() != null && deviceHelper.getCaptureInfo().getImage() != null) {
					try {
						renderJPGImageData(socket, deviceHelper.getCaptureInfo().getImage());
					} catch (Exception ex) {
						LOGGER.error("processLiveStreamInfo :: Exception ::", ex);
						break;
					}
				}

				Thread.sleep(30);
			}
			if (deviceHelper.getCaptureInfo() != null) {
				deviceHelper.deInitDevice();
				deviceHelper.setDeviceStatus(SBIConstant.DEVICE_STATUS_ISREADY);
			}
			if (streamTimeOut)
				response = SBIJsonInfo.getStreamErrorJson(lang, "609", "");
			else
				response = SBIJsonInfo.getStreamErrorJson(lang, "0", "");
		} catch (Exception ex) {
			response = SBIJsonInfo.getStreamErrorJson(lang, "610", ex.getLocalizedMessage());
			LOGGER.error("processLiveStreamInfo", ex);
		} finally {
			try {
				if (semaphore != null)
					semaphore.release();
			} catch (Exception ex) {
			}
		}
		return response;
	}

	/*
		private String processRCaptureInfo(SBIMockService mockService) {
			String response = null;
			String lang = "en";
			String specVersion = "";
			SBIDeviceHelper deviceHelper = null;
			try {
				if (!mockService.getPurpose().equals(ApplicationPropertyHelper.getPropertyKeyValue(SBIConstant.MOSIP_PURPOSE_REGISTRATION))) {
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "709", "", true);
				}

				String deviceId = "", deviceType = "", env = "", purpose = "";
				int deviceSubId = 0;
				CaptureRequestDto requestObject = (CaptureRequestDto) getRequestJson(SBIConstant.MOSIP_RCAPTURE_VERB);
				List<CaptureRequestDeviceDetailDto> mosipBioRequest = null;
				// if Null Throw Errors here
				if (requestObject != null) {
					mosipBioRequest = requestObject.getBio();
					if (mosipBioRequest != null && mosipBioRequest.size() > 0) {
						deviceId = requestObject.getBio().get(0).getDeviceId();
						deviceSubId = Integer.parseInt(requestObject.getBio().get(0).getDeviceSubId());
						deviceType = requestObject.getBio().get(0).getType();
						env = requestObject.getEnv();
						purpose = requestObject.getPurpose();
					}
				}

				LOGGER.info("processRCaptureInfo :: deviceId :: " + deviceId + " :: deviceSubId ::" + deviceSubId);
				if (env == null || env.trim().length() == 0) {
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "115", "", true);
				} else if (env != null && env.trim().length() > 0 && !(env.equals(SBIConstant.ENVIRONMENT_STAGING) || env.equals(SBIConstant.ENVIRONMENT_DEVELOPER) || env.equals(SBIConstant.ENVIRONMENT_PRE_PRODUCTION) || env.equals(SBIConstant.ENVIRONMENT_PRODUCTION))) {
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "115", "", true);
				} else if (purpose != null && purpose.trim().length() > 0 && !(purpose.equals(SBIConstant.PURPOSE_REGISTRATION))) {
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "121", "", true);
				}

				if (deviceId != null && deviceId.trim().length() == 0) {
					//return SBIJsonInfo.getErrorJson (lang, "704", "");
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "704", "", true);
				}
				if (deviceType == null || deviceType.trim().length() == 0) {
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "114", "", true);
				}

				if (deviceType != null && deviceType.trim().length() > 0 &&
						!(
								deviceType.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER) ||
										deviceType.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS) ||
										deviceType.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE))
				) {
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "114", "", true);
				}

				deviceHelper = getDeviceHelperForDeviceId(mockService, deviceId);
				if (deviceHelper == null || deviceHelper.getDeviceInfo() == null) {
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "705", "", true);
				}
				if (deviceType != null && deviceHelper.getDeviceType().equals(deviceType) == false) {
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "120", "", true);
				}

				if (deviceHelper.getDeviceInfo() != null && !deviceHelper.getDeviceInfo().getPurpose().equals(SBIConstant.PURPOSE_REGISTRATION)) {
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "706", "", true);
				}
				if (deviceHelper.getCaptureInfo() != null &&
						(!deviceHelper.getDeviceId().equalsIgnoreCase(deviceId) &&
								deviceHelper.getDeviceSubId() != deviceSubId)) {
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "702", "", true);
				}

				if (deviceHelper.getDeviceInfo() != null && deviceHelper.getDeviceInfo().getDeviceStatus().equals(SBIConstant.DEVICE_STATUS_NOTREGISTERED)) {
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "100", "", true);
				}
				if (deviceHelper.getDeviceInfo() != null && deviceHelper.getDeviceInfo().getDeviceStatus().equals(SBIConstant.DEVICE_STATUS_NOTREADY)) {
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "110", "", true);
				}
				if (!StringHelper.isAlphaNumericHyphenWithMinMaxLength(requestObject.getTransactionId())) {
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "112", "", true);
				}

				String bioType = mosipBioRequest.get(0).getType();
				String[] bioException = mosipBioRequest.get(0).getException();// Bio exceptions
				String[] bioSubtype = mosipBioRequest.get(0).getBioSubType();// Bio subtype
				int count = Integer.parseInt(mosipBioRequest.get(0).getCount());
				int exceptionCount = (bioException != null ? bioException.length : 0);
				int bioSubtypeCount = (bioSubtype != null ? bioSubtype.length : 0);
				int finalCount = count + exceptionCount;

				if (bioSubtypeCount != 0 && !isValidBioSubtypeValues(bioType, bioSubtype, false)) {
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "122", "", true);
				}
				if (exceptionCount != 0 && !isValidBioExceptionValues(bioType, bioException)) {
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "122", "", true);
				}

				switch (bioType) {
					case SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER:
						switch (deviceSubId) {
							case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT:
								// Max Count = 4 exception allowed
								if (finalCount != 4)
									return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "109", "", true);
								break;
							case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT:
								// Max Count = 4 exception allowed
								if (finalCount != 4)
									return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "109", "", true);
								break;
							case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_THUMB:
								// Max Count = 2 exception allowed
								if (finalCount != 2)
									return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "109", "", true);
								break;
							case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_INDEX:
							case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_MIDDLE:
							case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_RING:
							case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_LITTLE:
							case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_INDEX:
							case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_MIDDLE:
							case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_RING:
							case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_LITTLE:
							case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_THUMB:
							case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_THUMB:
								// Individual finger capture - exactly 1 finger, optionally reported as an exception
								if (finalCount != 1)
									return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "109", "", true);
								break;
							default:
								break;
						}
						break;
					case SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS:
						switch (deviceSubId) {
							case SBIConstant.DEVICE_IRIS_DOUBLE_SUB_TYPE_ID_LEFT:
								// Max Count = 1 no exception allowed
								if (count != 1 || exceptionCount != 0)
									return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "109", "", true);
								break;
							case SBIConstant.DEVICE_IRIS_DOUBLE_SUB_TYPE_ID_RIGHT:
								// Max Count = 1 no exception allowed
								if (count != 1 || exceptionCount != 0)
									return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "109", "", true);
								break;
							case SBIConstant.DEVICE_IRIS_DOUBLE_SUB_TYPE_ID_BOTH:
								// Max Count = 2 exception allowed
								finalCount = count + exceptionCount;
								if (finalCount != 2)
									return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "109", "", true);
								break;
							default:
								break;
						}
						break;
					case SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE:
						// Max Face Count = 1 with or without exception
						if (count != 1)
							return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "109", "", true);
						break;
					default:
						break;
				}
						break;
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_INDEX:
						if (bioExceptionInfo.getChkMissingLeftIndex() == SBICheckState.Unchecked)
						{
							if (captureInfo.getBioValueLI() != null && captureInfo.getBioValueLI().length() > 0)
							{
								BioMetricsDto bioDto = getBiometricData (transactionId, requestObject, deviceHelper, previousHash, bioType, SBIConstant.BIO_NAME_LEFT_INDEX,
										captureInfo.getBioValueLI(), captureInfo.getCaptureScoreLI(), requestScore, "", "0", isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
							else
							{
								BioMetricsDto bioDto = getBiometricErrorData (lang, specVersion, isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add (bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}
						break;
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_MIDDLE:
						if (bioExceptionInfo.getChkMissingLeftMiddle() == SBICheckState.Unchecked)
						{
							if (captureInfo.getBioValueLM() != null && captureInfo.getBioValueLM().length() > 0)
							{
								BioMetricsDto bioDto = getBiometricData (transactionId, requestObject, deviceHelper, previousHash, bioType, SBIConstant.BIO_NAME_LEFT_MIDDLE,
										captureInfo.getBioValueLM(), captureInfo.getCaptureScoreLM(), requestScore, "", "0", isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
							else
							{
								BioMetricsDto bioDto = getBiometricErrorData (lang, specVersion, isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add (bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}
						break;
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_RING:
						if (bioExceptionInfo.getChkMissingLeftRing() == SBICheckState.Unchecked)
						{
							if (captureInfo.getBioValueLR() != null && captureInfo.getBioValueLR().length() > 0)
							{
								BioMetricsDto bioDto = getBiometricData (transactionId, requestObject, deviceHelper, previousHash, bioType, SBIConstant.BIO_NAME_LEFT_RING,
										captureInfo.getBioValueLR(), captureInfo.getCaptureScoreLR(), requestScore, "", "0", isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
							else
							{
								BioMetricsDto bioDto = getBiometricErrorData (lang, specVersion, isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add (bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}
						break;
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_LITTLE:
						if (bioExceptionInfo.getChkMissingLeftLittle() == SBICheckState.Unchecked)
						{
							if (captureInfo.getBioValueLL() != null && captureInfo.getBioValueLL().length() > 0)
							{
								BioMetricsDto bioDto = getBiometricData (transactionId, requestObject, deviceHelper, previousHash, bioType, SBIConstant.BIO_NAME_LEFT_LITTLE,
										captureInfo.getBioValueLL(), captureInfo.getCaptureScoreLL(), requestScore, "", "0", isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
							else
							{
								BioMetricsDto bioDto = getBiometricErrorData (lang, specVersion, isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add (bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}
						break;
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_INDEX:
						if (bioExceptionInfo.getChkMissingRightIndex() == SBICheckState.Unchecked)
						{
							if (captureInfo.getBioValueRI() != null && captureInfo.getBioValueRI().length() > 0)
							{
								BioMetricsDto bioDto = getBiometricData (transactionId, requestObject, deviceHelper, previousHash, bioType, SBIConstant.BIO_NAME_RIGHT_INDEX,
										captureInfo.getBioValueRI(), captureInfo.getCaptureScoreRI(), requestScore, "", "0", isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
							else
							{
								BioMetricsDto bioDto = getBiometricErrorData (lang, specVersion, isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add (bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}
						break;
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_MIDDLE:
						if (bioExceptionInfo.getChkMissingRightMiddle() == SBICheckState.Unchecked)
						{
							if (captureInfo.getBioValueRM() != null && captureInfo.getBioValueRM().length() > 0)
							{
								BioMetricsDto bioDto = getBiometricData (transactionId, requestObject, deviceHelper, previousHash, bioType, SBIConstant.BIO_NAME_RIGHT_MIDDLE,
										captureInfo.getBioValueRM(), captureInfo.getCaptureScoreRM(), requestScore, "", "0", isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
							else
							{
								BioMetricsDto bioDto = getBiometricErrorData (lang, specVersion, isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add (bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}
						break;
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_RING:
						if (bioExceptionInfo.getChkMissingRightRing() == SBICheckState.Unchecked)
						{
							if (captureInfo.getBioValueRR() != null && captureInfo.getBioValueRR().length() > 0)
							{
								BioMetricsDto bioDto = getBiometricData (transactionId, requestObject, deviceHelper, previousHash, bioType, SBIConstant.BIO_NAME_RIGHT_RING,
										captureInfo.getBioValueRR(), captureInfo.getCaptureScoreRR(), requestScore, "", "0", isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
							else
							{
								BioMetricsDto bioDto = getBiometricErrorData (lang, specVersion, isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add (bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}
						break;
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_LITTLE:
						if (bioExceptionInfo.getChkMissingRightLittle() == SBICheckState.Unchecked)
						{
							if (captureInfo.getBioValueRL() != null && captureInfo.getBioValueRL().length() > 0)
							{
								BioMetricsDto bioDto = getBiometricData (transactionId, requestObject, deviceHelper, previousHash, bioType, SBIConstant.BIO_NAME_RIGHT_LITTLE,
										captureInfo.getBioValueRL(), captureInfo.getCaptureScoreRL(), requestScore, "", "0", isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
							else
							{
								BioMetricsDto bioDto = getBiometricErrorData (lang, specVersion, isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add (bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}
							break;
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_THUMB:
						if (bioExceptionInfo.getChkMissingLeftThumb() == SBICheckState.Unchecked)
						{
							if (captureInfo.getBioValueLT() != null && captureInfo.getBioValueLT().length() > 0)
							{
								BioMetricsDto bioDto = getBiometricData (transactionId, requestObject, deviceHelper, previousHash, bioType, SBIConstant.BIO_NAME_LEFT_THUMB,
										captureInfo.getBioValueLT(), captureInfo.getCaptureScoreLT(), requestScore, "", "0", isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
							else
							{
								BioMetricsDto bioDto = getBiometricErrorData (lang, specVersion, isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add (bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}
						break;
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_THUMB:
						if (bioExceptionInfo.getChkMissingRightThumb() == SBICheckState.Unchecked)
						{
							if (captureInfo.getBioValueRT() != null && captureInfo.getBioValueRT().length() > 0)
							{
								BioMetricsDto bioDto = getBiometricData (transactionId, requestObject, deviceHelper, previousHash, bioType, SBIConstant.BIO_NAME_RIGHT_THUMB,
										captureInfo.getBioValueRT(), captureInfo.getCaptureScoreRT(), requestScore, "", "0", isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
							else
							{
								BioMetricsDto bioDto = getBiometricErrorData (lang, specVersion, isForAuthenication);
								if (bioDto != null)
								{
									biometrics.add (bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}
						break;
				}

				if (deviceHelper.getDeviceInfo() != null && deviceHelper.getDeviceInfo().getDeviceStatus().equals(SBIConstant.DEVICE_STATUS_ISREADY))
				{
					deviceHelper.initDevice();
					deviceHelper.setDeviceId(deviceId);
					deviceHelper.setDeviceSubId(deviceSubId);
					deviceHelper.setDeviceStatus(SBIConstant.DEVICE_STATUS_ISBUSY);
				}
				else if (deviceHelper.getDeviceInfo() != null && deviceHelper.getDeviceInfo().getDeviceStatus().equals(SBIConstant.DEVICE_STATUS_ISBUSY))
				{
					if (deviceHelper.getCaptureInfo() == null || deviceHelper.getCaptureInfo().isCaptureStarted())
						return SBIJsonInfo.getCaptureErrorJson  (specVersion, lang, "703", "", true);

				}

				int timeout = Integer.parseInt(requestObject.getTimeout()+ "");
				int requestScore = Integer.parseInt(mosipBioRequest.get(0).getRequestedScore() + "");

				specVersion = requestObject.getSpecVersion();
				int returnCode = -1;
				long startTime = System.currentTimeMillis();
				long endTime = startTime + timeout;
				boolean captureStarted = false;
				boolean captureTimeOut = false;
				boolean captureLiveStreamEnded = false;
				long delay = deviceHelper.getDelayForMethod(SBIConstant.MOSIP_METHOD_RCAPTURE);
				while (true)
				{
					if (!captureStarted)
					{
						deviceHelper.setProfileId(mockService.getProfileId());

						if (bioException != null && !bioType.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE))
							deviceHelper.getCaptureInfo().getBioExceptionInfo().initBioException(bioException);

						deviceHelper.getCaptureInfo().setRequestScore(requestScore);
						deviceHelper.getCaptureInfo().setCaptureStarted(true);
						captureStarted = true;
					}
					delay(delay);
					try
					{
						if (System.currentTimeMillis () > endTime)
						{
							captureTimeOut = true;
							break;
						}
						// acquiring the lock
						if (semaphore != null)
							semaphore.acquire();

						if (deviceHelper.getCaptureInfo() == null)
						{
							captureLiveStreamEnded = true;
							break;
						}

						returnCode = deviceHelper.getBioCapture(false);

						if (deviceHelper.getCaptureInfo() != null && deviceHelper.getCaptureInfo().isCaptureCompleted())
						{
							break;
						}
					}
					catch (Exception ex)
					{ }
					finally
					{
						try
						{
							if (semaphore != null)
								semaphore.release();
						}
						catch (Exception ex)
						{ }
					}

					Thread.sleep (30);
				}

				if (captureLiveStreamEnded)
				{
					response = SBIJsonInfo.getCaptureErrorJson  (specVersion, lang, "700", "", true);
				}
				else if (captureTimeOut)
				{
					response = SBIJsonInfo.getCaptureErrorJson  (specVersion, lang, "701", "", true);
					if (deviceHelper.getCaptureInfo() == null)
						deviceHelper.getCaptureInfo().setCaptureCompleted(true);
				}
				else
				{
					List<BioMetricsDto> biometrics = getBioMetricsDtoList (lang, requestObject, deviceHelper, deviceSubId, false);
					if (biometrics != null && biometrics.size() > 0)
					{
						RCaptureResponse captureResponse = new RCaptureResponse ();
						captureResponse.setBiometrics(biometrics);

						ObjectMapper mapper = new ObjectMapper ();
						SerializationConfig config = mapper.getSerializationConfig();
						config.setSerializationInclusion(Inclusion.NON_NULL);
						mapper.setSerializationConfig(config);

						response = mapper.writeValueAsString(captureResponse);
					}
					else
					{
						response = SBIJsonInfo.getCaptureErrorJson  (specVersion, lang, "708", "", true);
					}

					deviceHelper.deInitDevice();
					deviceHelper.setDeviceStatus(SBIConstant.DEVICE_STATUS_ISREADY);
				}

				if (deviceHelper.getCaptureInfo() != null)
				{
					deviceHelper.getCaptureInfo().getBioExceptionInfo().deInitBioException();
					// When Capture is called After LiveStreaming is called
					// DeInit is called in Livestream method
					if (deviceHelper.getCaptureInfo().isLiveStreamStarted())
					{
						deviceHelper.getCaptureInfo().setCaptureStarted(false);
						deviceHelper.getCaptureInfo().setCaptureCompleted(true);
					}
					// DeInit When Capture is called Directly
					else
					{
						deviceHelper.deInitDevice();
						deviceHelper.setDeviceStatus(SBIConstant.DEVICE_STATUS_ISREADY);
					}
				}
			}*/
       /* catch (Exception ex)
        {
            response = SBIJsonInfo.getCaptureErrorJson (specVersion, lang, "710", "", true);
            LOGGER.error("processRCaptureInfo", ex);
        }
        finally
        {
        	try
            {
        		if (semaphore != null)
        			semaphore.release ();
            }
            catch (Exception ex)
            {
            }
        }
        return response;
	}
}*/
	private String processRCaptureInfo(SBIMockService mockService) {

		String response = null;
		String lang = "en";
		String specVersion = "";
		SBIDeviceHelper deviceHelper = null;

		try {

			/*
			 * ---------------------------------------------------------
			 * 1. Validate purpose
			 * ---------------------------------------------------------
			 */
			if (mockService == null ||
					mockService.getPurpose() == null ||
					!mockService.getPurpose().equals(
							ApplicationPropertyHelper.getPropertyKeyValue(
									SBIConstant.MOSIP_PURPOSE_REGISTRATION))) {

				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "709", "", true);
			}

			String deviceId = "";
			String deviceType = "";
			String env = "";
			String purpose = "";
			int deviceSubId = 0;

			/*
			 * ---------------------------------------------------------
			 * 2. Get Capture Request
			 * ---------------------------------------------------------
			 */
			CaptureRequestDto requestObject =
					(CaptureRequestDto) getRequestJson(
							SBIConstant.MOSIP_RCAPTURE_VERB);

			if (requestObject == null) {
				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "710", "", true);
			}

			List<CaptureRequestDeviceDetailDto> mosipBioRequest =
					requestObject.getBio();

			if (mosipBioRequest == null || mosipBioRequest.size() == 0) {
				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "710", "", true);
			}

			/*
			 * ---------------------------------------------------------
			 * 3. Read request values
			 * ---------------------------------------------------------
			 */
			CaptureRequestDeviceDetailDto bioRequest =
					mosipBioRequest.get(0);

			if (bioRequest == null) {
				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "710", "", true);
			}

			deviceId = bioRequest.getDeviceId();

			if (bioRequest.getDeviceSubId() != null &&
					bioRequest.getDeviceSubId().trim().length() > 0) {

				deviceSubId =
						Integer.parseInt(bioRequest.getDeviceSubId());
			}

			deviceType = bioRequest.getType();
			env = requestObject.getEnv();
			purpose = requestObject.getPurpose();

			specVersion = requestObject.getSpecVersion();

			LOGGER.info(
					"processRCaptureInfo :: deviceId :: "
							+ deviceId
							+ " :: deviceSubId :: "
							+ deviceSubId
							+ " :: deviceType :: "
							+ deviceType);

			/*
			 * ---------------------------------------------------------
			 * 4. Validate environment
			 * ---------------------------------------------------------
			 */
			if (env == null || env.trim().length() == 0) {

				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "115", "", true);
			}

			if (!(env.equals(SBIConstant.ENVIRONMENT_STAGING)
					|| env.equals(SBIConstant.ENVIRONMENT_DEVELOPER)
					|| env.equals(SBIConstant.ENVIRONMENT_PRE_PRODUCTION)
					|| env.equals(SBIConstant.ENVIRONMENT_PRODUCTION))) {

				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "115", "", true);
			}

			/*
			 * ---------------------------------------------------------
			 * 5. Validate purpose
			 * ---------------------------------------------------------
			 */
			if (purpose != null &&
					purpose.trim().length() > 0 &&
					!purpose.equals(SBIConstant.PURPOSE_REGISTRATION)) {

				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "121", "", true);
			}

			/*
			 * ---------------------------------------------------------
			 * 6. Validate device ID
			 * ---------------------------------------------------------
			 */
			if (deviceId == null || deviceId.trim().length() == 0) {

				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "704", "", true);
			}

			/*
			 * ---------------------------------------------------------
			 * 7. Validate device type
			 * ---------------------------------------------------------
			 */
			if (deviceType == null ||
					deviceType.trim().length() == 0) {

				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "114", "", true);
			}

			if (!(deviceType.equals(
					SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER)
					|| deviceType.equals(
					SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS)
					|| deviceType.equals(
					SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE))) {

				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "114", "", true);
			}

			/*
			 * ---------------------------------------------------------
			 * 8. Get Device Helper
			 * ---------------------------------------------------------
			 */
			/*
			 * ---------------------------------------------------------
			 /*
 * =========================================================
 *             DEVICE LOOKUP DEBUG
 * =========================================================
 */

			LOGGER.info("========== DEVICE LOOKUP DEBUG ==========");

			LOGGER.info("RCapture Request:");
			LOGGER.info("  deviceId      :: " + deviceId);
			LOGGER.info("  deviceSubId    :: " + deviceSubId);
			LOGGER.info("  deviceType     :: " + deviceType);
			LOGGER.info("  purpose        :: " + purpose);
			LOGGER.info("  MockSBI purpose:: " + mockService.getPurpose());

			deviceHelper = getDeviceHelperForDeviceId(mockService, deviceId);

			if (deviceHelper == null) {

				LOGGER.error("========== DEVICE LOOKUP FAILED ==========");
				LOGGER.error("No SBIDeviceHelper found for deviceId :: " + deviceId);
				LOGGER.error("Requested deviceSubId :: " + deviceSubId);
				LOGGER.error("Requested deviceType  :: " + deviceType);
				LOGGER.error("Requested purpose     :: " + purpose);
				LOGGER.error("==========================================");

				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "705", "", true);
			}

			LOGGER.info("========== DEVICE HELPER FOUND ==========");

			LOGGER.info("Helper deviceId     :: " + deviceHelper.getDeviceId());
			LOGGER.info("Helper deviceSubId  :: " + deviceHelper.getDeviceSubId());
			LOGGER.info("Helper deviceType   :: " + deviceHelper.getDeviceType());
			LOGGER.info("Helper deviceSubType:: " + deviceHelper.getDeviceSubType());
			LOGGER.info("Helper purpose      :: " + deviceHelper.getPurpose());
			LOGGER.info("Helper status       :: " + deviceHelper.getDeviceStatus());

			if (deviceHelper.getDeviceInfo() == null) {

				LOGGER.error("DeviceHelper found but DeviceInfo is NULL");
				LOGGER.error("deviceId :: " + deviceId);

				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "705", "", true);
			}

			LOGGER.info("========== DEVICE INFO ==========");

			LOGGER.info("DeviceInfo.deviceId     :: "
					+ deviceHelper.getDeviceInfo().getDeviceId());

			LOGGER.info("DeviceInfo.deviceStatus :: "
					+ deviceHelper.getDeviceInfo().getDeviceStatus());

			LOGGER.info("DeviceInfo.purpose      :: "
					+ deviceHelper.getDeviceInfo().getPurpose());

			LOGGER.info("DeviceInfo.deviceCode   :: "
					+ deviceHelper.getDeviceInfo().getDeviceCode());

			LOGGER.info("Requested deviceSubId   :: " + deviceSubId);
			LOGGER.info("Helper deviceSubId      :: "
					+ deviceHelper.getDeviceSubId());

			LOGGER.info("==========================================");

			/*
			 * ---------------------------------------------------------
			 * 9. Validate device type
			 * ---------------------------------------------------------
			 */
			if (!deviceHelper.getDeviceType().equals(deviceType)) {

				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "120", "", true);
			}

			/*
			 * ---------------------------------------------------------
			 * 10. Validate device purpose
			 * ---------------------------------------------------------
			 */
			if (deviceHelper.getDeviceInfo().getPurpose() == null ||
					!deviceHelper.getDeviceInfo().getPurpose()
							.equals(SBIConstant.PURPOSE_REGISTRATION)) {

				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "706", "", true);
			}

			/*
			 * ---------------------------------------------------------
			 * 11. Validate existing capture information
			 * ---------------------------------------------------------
			 */
			if (deviceHelper.getCaptureInfo() != null) {

				if (!deviceHelper.getDeviceId()
						.equalsIgnoreCase(deviceId)
						|| deviceHelper.getDeviceSubId() != deviceSubId) {

					return SBIJsonInfo.getCaptureErrorJson(
							specVersion, lang, "702", "", true);
				}
			}

			/*
			 * ---------------------------------------------------------
			 * 12. Validate device status
			 * ---------------------------------------------------------
			 */
			if (deviceHelper.getDeviceInfo()
					.getDeviceStatus()
					.equals(SBIConstant.DEVICE_STATUS_NOTREGISTERED)) {

				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "100", "", true);
			}

			if (deviceHelper.getDeviceInfo()
					.getDeviceStatus()
					.equals(SBIConstant.DEVICE_STATUS_NOTREADY)) {

				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "110", "", true);
			}

			/*
			 * ---------------------------------------------------------
			 * 13. Validate transaction ID
			 * ---------------------------------------------------------
			 */
			if (!StringHelper.isAlphaNumericHyphenWithMinMaxLength(
					requestObject.getTransactionId())) {

				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "112", "", true);
			}

			/*
			 * ---------------------------------------------------------
			 * 14. Read biometric request
			 * ---------------------------------------------------------
			 */
			String bioType = bioRequest.getType();

			String[] bioException =
					bioRequest.getException();

			String[] bioSubtype =
					bioRequest.getBioSubType();

			int count =
					Integer.parseInt(bioRequest.getCount());

			int exceptionCount =
					bioException != null ? bioException.length : 0;

			int bioSubtypeCount =
					bioSubtype != null ? bioSubtype.length : 0;

			int finalCount =
					count + exceptionCount;
			LOGGER.info("========== RCAPTURE DEBUG ==========");
			LOGGER.info("bioType       :: " + bioType);
			LOGGER.info("deviceSubId   :: " + deviceSubId);
			LOGGER.info("count         :: " + count);
			LOGGER.info("exceptionCnt  :: " + exceptionCount);
			LOGGER.info("finalCount    :: " + finalCount);

			if (bioSubtype != null) {
				for (String subtype : bioSubtype) {
					LOGGER.info("bioSubtype    :: " + subtype);
				}
			}

			if (bioException != null) {
				for (String exception : bioException) {
					LOGGER.info("bioException  :: " + exception);
				}
			}

			/*
			 * ---------------------------------------------------------
			 * 15. Validate biometric subtype
			 * ---------------------------------------------------------
			 */
			if (bioSubtypeCount != 0 &&
					!isValidBioSubtypeValues(
							bioType,
							bioSubtype,
							false)) {

				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "122", "", true);
			}

			/*
			 * ---------------------------------------------------------
			 * 16. Validate biometric exceptions
			 * ---------------------------------------------------------
			 */
			if (exceptionCount != 0 &&
					!isValidBioExceptionValues(
							bioType,
							bioException)) {

				return SBIJsonInfo.getCaptureErrorJson(
						specVersion, lang, "122", "", true);
			}

			/*
			 * ---------------------------------------------------------
			 * 17. Validate count based on biometric type
			 *
			 * IMPORTANT:
			 * Individual finger cases belong INSIDE the
			 * switch(deviceSubId).
			 * ---------------------------------------------------------
			 */
			switch (bioType) {

				case SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER:

					switch (deviceSubId) {

						/*
						 * LEFT SLAP
						 * 4 fingers
						 */
						case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT:

							if (finalCount != 4) {

								return SBIJsonInfo.getCaptureErrorJson(
										specVersion,
										lang,
										"109",
										"",
										true);
							}

							break;

						/*
						 * RIGHT SLAP
						 * 4 fingers
						 */
						case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT:

							if (finalCount != 4) {

								return SBIJsonInfo.getCaptureErrorJson(
										specVersion,
										lang,
										"109",
										"",
										true);
							}

							break;

						/*
						 * BOTH THUMBS
						 * 2 fingers
						 */
						case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_THUMB:

							if (finalCount != 2) {

								return SBIJsonInfo.getCaptureErrorJson(
										specVersion,
										lang,
										"109",
										"",
										true);
							}

							break;

						/*
						 * -------------------------------------------------
						 * INDIVIDUAL FINGERS
						 *
						 * Each individual finger = exactly 1
						 * count + exception.
						 * -------------------------------------------------
						 */
						case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_INDEX:
						case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_INDEX:
						case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_MIDDLE:
						case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_MIDDLE:
						case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_RING:
						case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_RING:
						case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_LITTLE:
						case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_LITTLE:
						case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_THUMB:
						case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_THUMB:

							// One individual finger = count 1

							if (deviceSubId >= 4 && deviceSubId <= 13) {
								finalCount = 1;
							}
							if (finalCount != 1)
								return SBIJsonInfo.getCaptureErrorJson(
										specVersion, lang, "109", "", true);
							break;

						default:

							return SBIJsonInfo.getCaptureErrorJson(
									specVersion,
									lang,
									"109",
									"",
									true);
					}

					break;

				/*
				 * -----------------------------------------------------
				 * IRIS
				 * -----------------------------------------------------
				 */
				case SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS:

					switch (deviceSubId) {

						case SBIConstant.DEVICE_IRIS_DOUBLE_SUB_TYPE_ID_LEFT:

						case SBIConstant.DEVICE_IRIS_DOUBLE_SUB_TYPE_ID_RIGHT:

							/*
							 * One iris and no exception
							 */
							if (count != 1 ||
									exceptionCount != 0) {

								return SBIJsonInfo.getCaptureErrorJson(
										specVersion,
										lang,
										"109",
										"",
										true);
							}

							break;

						case SBIConstant.DEVICE_IRIS_DOUBLE_SUB_TYPE_ID_BOTH:

							/*
							 * Two iris
							 */
							if (finalCount != 2) {

								return SBIJsonInfo.getCaptureErrorJson(
										specVersion,
										lang,
										"109",
										"",
										true);
							}

							break;

						default:

							return SBIJsonInfo.getCaptureErrorJson(
									specVersion,
									lang,
									"109",
									"",
									true);
					}

					break;

				/*
				 * -----------------------------------------------------
				 * FACE
				 * -----------------------------------------------------
				 */
				case SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE:

					if (count != 1) {

						return SBIJsonInfo.getCaptureErrorJson(
								specVersion,
								lang,
								"109",
								"",
								true);
					}

					break;

				default:

					return SBIJsonInfo.getCaptureErrorJson(
							specVersion,
							lang,
							"114",
							"",
							true);
			}

			/*
			 * ---------------------------------------------------------
			 * 18. Initialize device
			 * ---------------------------------------------------------
			 */
			if (deviceHelper.getDeviceInfo()
					.getDeviceStatus()
					.equals(SBIConstant.DEVICE_STATUS_ISREADY)) {

				deviceHelper.initDevice();

				deviceHelper.setDeviceId(deviceId);
				deviceHelper.setDeviceSubId(deviceSubId);

				deviceHelper.setDeviceStatus(
						SBIConstant.DEVICE_STATUS_ISBUSY);
			}

			/*
			 * ---------------------------------------------------------
			 * 19. Check device busy status
			 * ---------------------------------------------------------
			 */
			else if (deviceHelper.getDeviceInfo()
					.getDeviceStatus()
					.equals(SBIConstant.DEVICE_STATUS_ISBUSY)) {

				if (deviceHelper.getCaptureInfo() == null ||
						deviceHelper.getCaptureInfo().isCaptureStarted()) {

					return SBIJsonInfo.getCaptureErrorJson(
							specVersion,
							lang,
							"703",
							"",
							true);
				}
			}

			/*
			 * ---------------------------------------------------------
			 * 20. Request timeout and score
			 * ---------------------------------------------------------
			 */
			int timeout =
					Integer.parseInt(requestObject.getTimeout() + "");

			int requestScore =
					Integer.parseInt(
							bioRequest.getRequestedScore() + "");

			long startTime =
					System.currentTimeMillis();

			long endTime =
					startTime + timeout;

			boolean captureStarted = false;
			boolean captureTimeOut = false;
			boolean captureLiveStreamEnded = false;

			long delay =
					deviceHelper.getDelayForMethod(
							SBIConstant.MOSIP_METHOD_RCAPTURE);

			/*
			 * ---------------------------------------------------------
			 * 21. Capture loop
			 * ---------------------------------------------------------
			 */
			while (true) {

				if (!captureStarted) {

					deviceHelper.setProfileId(
							mockService.getProfileId());

					if (bioException != null &&
							!bioType.equals(
									SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE)) {

						if (deviceHelper.getCaptureInfo() != null) {

							deviceHelper.getCaptureInfo()
									.getBioExceptionInfo()
									.initBioException(bioException);
						}
					}

					if (deviceHelper.getCaptureInfo() != null) {

						deviceHelper.getCaptureInfo()
								.setRequestScore(requestScore);

						deviceHelper.getCaptureInfo()
								.setCaptureStarted(true);
					}

					captureStarted = true;
				}

				delay(delay);

				boolean semaphoreAcquired = false;

				try {

					/*
					 * Timeout check
					 */
					if (System.currentTimeMillis() > endTime) {

						captureTimeOut = true;
						break;
					}

					/*
					 * Acquire lock
					 */
					if (semaphore != null) {

						semaphore.acquire();
						semaphoreAcquired = true;
					}

					/*
					 * Capture information can disappear
					 */
					if (deviceHelper.getCaptureInfo() == null) {

						captureLiveStreamEnded = true;
						break;
					}

					/*
					 * Perform biometric capture
					 */
					deviceHelper.getBioCapture(false);

					/*
					 * Capture completed
					 */
					if (deviceHelper.getCaptureInfo() != null &&
							deviceHelper.getCaptureInfo()
									.isCaptureCompleted()) {

						break;
					}

				} catch (Exception ex) {

					LOGGER.error(
							"Exception during biometric capture",
							ex);

				} finally {

					/*
					 * Release only if this iteration acquired it.
					 */
					if (semaphore != null &&
							semaphoreAcquired) {

						try {
							semaphore.release();
						} catch (Exception ex) {
							LOGGER.error(
									"Error releasing semaphore",
									ex);
						}
					}
				}

				Thread.sleep(30);
			}

			/*
			 * ---------------------------------------------------------
			 * 22. Capture result
			 * ---------------------------------------------------------
			 */

			if (captureLiveStreamEnded) {

				response =
						SBIJsonInfo.getCaptureErrorJson(
								specVersion,
								lang,
								"700",
								"",
								true);
			} else if (captureTimeOut) {

				response =
						SBIJsonInfo.getCaptureErrorJson(
								specVersion,
								lang,
								"701",
								"",
								true);

				if (deviceHelper.getCaptureInfo() != null) {

					deviceHelper.getCaptureInfo()
							.setCaptureCompleted(true);
				}
			} else {

				/*
				 * -----------------------------------------------------
				 * IMPORTANT:
				 *
				 * Individual finger processing is done here through
				 * getBioMetricsDtoList().
				 * -----------------------------------------------------
				 */
				List<BioMetricsDto> biometrics =
						getBioMetricsDtoList(
								lang,
								requestObject,
								deviceHelper,
								deviceSubId,
								false);

				if (biometrics != null &&
						biometrics.size() > 0) {

					RCaptureResponse captureResponse =
							new RCaptureResponse();

					captureResponse.setBiometrics(
							biometrics);

					ObjectMapper mapper =
							new ObjectMapper();

					SerializationConfig config =
							mapper.getSerializationConfig();

					config.setSerializationInclusion(
							Inclusion.NON_NULL);

					mapper.setSerializationConfig(config);

					response =
							mapper.writeValueAsString(
									captureResponse);
				} else {

					response =
							SBIJsonInfo.getCaptureErrorJson(
									specVersion,
									lang,
									"708",
									"",
									true);
				}
			}

			/*
			 * ---------------------------------------------------------
			 * 23. Cleanup
			 * ---------------------------------------------------------
			 */
			if (deviceHelper != null &&
					deviceHelper.getCaptureInfo() != null) {

				deviceHelper.getCaptureInfo()
						.getBioExceptionInfo()
						.deInitBioException();

				/*
				 * Live stream was started earlier.
				 */
				if (deviceHelper.getCaptureInfo()
						.isLiveStreamStarted()) {

					deviceHelper.getCaptureInfo()
							.setCaptureStarted(false);

					deviceHelper.getCaptureInfo()
							.setCaptureCompleted(true);
				}

				/*
				 * Normal capture
				 */
				else {

					deviceHelper.deInitDevice();

					deviceHelper.setDeviceStatus(
							SBIConstant.DEVICE_STATUS_ISREADY);
				}
			}

		} catch (Exception ex) {

			response =
					SBIJsonInfo.getCaptureErrorJson(
							specVersion,
							lang,
							"710",
							"",
							true);

			LOGGER.error(
					"processRCaptureInfo",
					ex);
		}

		/*
		 * Do NOT release semaphore here.
		 *
		 * The semaphore acquired inside the capture loop
		 * is already released inside its finally block.
		 */

		return response;
	}

	private String processCaptureInfo(SBIMockService mockService) {
		String response = null;
		String lang = "en";
		String specVersion = "";
		SBIDeviceHelper deviceHelper = null;
		try {
			if (!mockService.getPurpose().equals(ApplicationPropertyHelper.getPropertyKeyValue(SBIConstant.MOSIP_PURPOSE_AUTH))) {
				return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "809", "", false);
			}

			String deviceId = "", deviceType = "", env = "", purpose = "";
			;
			int deviceSubId = 0;
			CaptureRequestDto requestObject = (CaptureRequestDto) getRequestJson(SBIConstant.MOSIP_RCAPTURE_VERB);
			List<CaptureRequestDeviceDetailDto> mosipBioRequest = null;
			// if Null Throw Errors here
			if (requestObject != null) {
				mosipBioRequest = requestObject.getBio();
				if (mosipBioRequest != null && mosipBioRequest.size() > 0) {
					deviceId = requestObject.getBio().get(0).getDeviceId();
					deviceSubId = Integer.parseInt(requestObject.getBio().get(0).getDeviceSubId());
					deviceType = requestObject.getBio().get(0).getType();
					env = requestObject.getEnv();
					purpose = requestObject.getPurpose();
				}
			}

			LOGGER.info("processCaptureInfo :: deviceId :: " + deviceId + " :: deviceSubId ::" + deviceSubId);

			if (env == null || env.trim().length() == 0) {
				return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "115", "", false);
			} else if (env != null && env.trim().length() > 0 && !(env.equals(SBIConstant.ENVIRONMENT_STAGING) || env.equals(SBIConstant.ENVIRONMENT_DEVELOPER) || env.equals(SBIConstant.ENVIRONMENT_PRE_PRODUCTION) || env.equals(SBIConstant.ENVIRONMENT_PRODUCTION))) {
				return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "115", "", false);
			} else if (purpose != null && purpose.trim().length() > 0 && !(purpose.equals(SBIConstant.PURPOSE_AUTH))) {
				return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "121", "", false);
			}

			if (deviceId == null || deviceId.trim().length() == 0) {
				return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "804", "", false);
			}
			if (deviceType == null || deviceType.trim().length() == 0) {
				return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "114", "", false);
			}

			if (deviceType != null && deviceType.trim().length() > 0 &&
					!(
							deviceType.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER) ||
									deviceType.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS) ||
									deviceType.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE))
			) {
				return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "114", "", false);
			}

			deviceHelper = getDeviceHelperForDeviceId(mockService, deviceId);
			if (deviceHelper == null || deviceHelper.getDeviceInfo() == null) {
				return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "805", "", false);
			}
			if (deviceType != null && deviceHelper.getDeviceType().equals(deviceType) == false) {
				return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "120", "", false);
			}

			if (deviceHelper.getDeviceInfo() != null && !deviceHelper.getDeviceInfo().getPurpose().equals(SBIConstant.PURPOSE_AUTH)) {
				return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "806", "", false);
			}
			if (deviceHelper.getDeviceInfo() != null && deviceHelper.getDeviceInfo().getDeviceStatus().equals(SBIConstant.DEVICE_STATUS_NOTREGISTERED)) {
				return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "100", "", false);
			}
			if (deviceHelper.getDeviceInfo() != null && deviceHelper.getDeviceInfo().getDeviceStatus().equals(SBIConstant.DEVICE_STATUS_NOTREADY)) {
				return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "110", "", false);
			}
			if (deviceHelper.getDeviceInfo() != null && deviceHelper.getDeviceInfo().getDeviceStatus().equals(SBIConstant.DEVICE_STATUS_ISBUSY)) {
				return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "111", "", false);
			}
			if (!StringHelper.isAlphaNumericHyphenWithMinMaxLength(requestObject.getTransactionId())) {
				return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "112", "", false);
			}

			String bioType = mosipBioRequest.get(0).getType();
			String[] bioSubType = mosipBioRequest.get(0).getBioSubType();// Bio Subtype
			int timeout = Integer.parseInt(requestObject.getTimeout() + "");

			int requestScore = Integer.parseInt(mosipBioRequest.get(0).getRequestedScore() + "");
			int bioCount = Integer.parseInt(mosipBioRequest.get(0).getCount() + "");

			if (!isValidBioSubtypeValues(bioType, bioSubType, true)) {
				return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "122", "", true);
			}
			if (deviceType != null) {
				if ((bioCount < 0 || bioCount > 10) && deviceType.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER))
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "109", "", false);
				if ((bioCount < 0 || bioCount > 2) && deviceType.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS))
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "109", "", false);
				if ((bioCount < 0 || bioCount > 1) && deviceType.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE))
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "109", "", false);
			}

			if (deviceHelper.getDeviceInfo() != null && deviceHelper.getDeviceInfo().getDeviceStatus().equals(SBIConstant.DEVICE_STATUS_ISREADY)) {
				deviceHelper.initDevice();
				deviceHelper.setDeviceId(deviceId);
				deviceHelper.setDeviceSubId(deviceSubId);
				deviceHelper.setDeviceStatus(SBIConstant.DEVICE_STATUS_ISBUSY);
			} else if (deviceHelper.getDeviceInfo() != null && deviceHelper.getDeviceInfo().getDeviceStatus().equals(SBIConstant.DEVICE_STATUS_ISBUSY)) {
				if (deviceHelper.getCaptureInfo().isCaptureStarted())
					return SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "803", "", false);
			}

			specVersion = requestObject.getSpecVersion();
			int returnCode = -1;
			long startTime = System.currentTimeMillis();
			long endTime = startTime + timeout;
			boolean captureStarted = false;
			boolean captureTimeOut = false;
			boolean captureLiveStreamEnded = false;
			long delay = deviceHelper.getDelayForMethod(SBIConstant.MOSIP_METHOD_CAPTURE);

			while (true) {
				if (!captureStarted) {
					deviceHelper.setProfileId(mockService.getProfileId());

					deviceHelper.getCaptureInfo().setBioCount(bioCount);
					deviceHelper.getCaptureInfo().setBioSubType(bioSubType);
					deviceHelper.getCaptureInfo().setRequestScore(requestScore);
					deviceHelper.getCaptureInfo().setCaptureStarted(true);
					captureStarted = true;
				}
				delay(delay);
				try {
					if (System.currentTimeMillis() > endTime) {
						captureTimeOut = true;
						break;
					}
					// acquiring the lock
					if (semaphore != null)
						semaphore.acquire();

					if (deviceHelper.getCaptureInfo() == null) {
						captureLiveStreamEnded = true;
						break;
					}

					returnCode = deviceHelper.getBioCapture(true);

					if (deviceHelper.getCaptureInfo() != null && deviceHelper.getCaptureInfo().isCaptureCompleted()) {
						break;
					}
				} catch (Exception ex) {
				} finally {
					try {
						if (semaphore != null)
							semaphore.release();
					} catch (Exception ex) {
					}
				}

				Thread.sleep(30);
			}

			if (captureLiveStreamEnded) {
				response = SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "800", "", false);
			} else if (captureTimeOut) {
				response = SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "801", "", false);
				if (deviceHelper.getCaptureInfo() == null)
					deviceHelper.getCaptureInfo().setCaptureCompleted(true);
			} else {
				List<BioMetricsDto> biometrics = null;
				try {
					biometrics = getBioMetricsDtoList(lang, requestObject, deviceHelper, deviceSubId, true);
					if (biometrics != null && biometrics.size() > 0) {
						RCaptureResponse captureResponse = new RCaptureResponse();
						captureResponse.setBiometrics(biometrics);

						ObjectMapper mapper = new ObjectMapper();
						SerializationConfig config = mapper.getSerializationConfig();
						config.setSerializationInclusion(Inclusion.NON_NULL);
						mapper.setSerializationConfig(config);

						response = mapper.writeValueAsString(captureResponse);
					} else {
						response = SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "708", "", false);
					}
				} catch (Exception ex) {
					response = SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "999", ex.getLocalizedMessage(), false);
				}

				deviceHelper.deInitDevice();
				deviceHelper.setDeviceStatus(SBIConstant.DEVICE_STATUS_ISREADY);
			}

			if (deviceHelper.getCaptureInfo() != null) {
				deviceHelper.getCaptureInfo().getBioExceptionInfo().deInitBioException();
				// When Capture is called After LiveStreaming is called
				// DeInit is called in Livestream method
				if (deviceHelper.getCaptureInfo().isLiveStreamStarted()) {
					deviceHelper.getCaptureInfo().setCaptureStarted(false);
					deviceHelper.getCaptureInfo().setCaptureCompleted(true);
				}
				// DeInit When Capture is called Directly
				else {
					deviceHelper.deInitDevice();
					deviceHelper.setDeviceStatus(SBIConstant.DEVICE_STATUS_ISREADY);
				}
			}
		} catch (Exception ex) {
			response = SBIJsonInfo.getCaptureErrorJson(specVersion, lang, "810", "", false);
			LOGGER.error("processCaptureInfo", ex);
		} finally {
			try {
				if (semaphore != null)
					semaphore.release();
			} catch (Exception ex) {
			}
		}
		return response;
	}

	private List<BioMetricsDto> getBioMetricsDtoList(
			String lang,
			CaptureRequestDto requestObject,
			SBIDeviceHelper deviceHelper,
			int deviceSubId,
			boolean isForAuthenication)
			throws JsonGenerationException, JsonMappingException, IOException,
			NoSuchAlgorithmException, DecoderException, SBIException {

		List<BioMetricsDto> biometrics = new ArrayList<BioMetricsDto>();

		String specVersion = requestObject.getSpecVersion();
		String transactionId = requestObject.getTransactionId();

		int captureScore = deviceHelper.getQualityScore(); // SET MANUALLY

		int requestScore = requestObject.getBio().get(0).getRequestedScore();
		int bioCount = Integer.parseInt(requestObject.getBio().get(0).getCount());

		String bioType = requestObject.getBio().get(0).getType();

		String[] bioExceptions =
				requestObject.getBio().get(0).getException();

		String[] bioSubType =
				requestObject.getBio().get(0).getBioSubType();

		String previousHash =
				requestObject.getBio().get(0).getPreviousHash();


		// ============================================================
		// REGISTRATION
		// ============================================================
		if (!isForAuthenication) {

			// ========================================================
			// FINGER
			// ========================================================
			if (deviceHelper.getDigitalId().getType()
					.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER)
					&&
					deviceHelper.getDigitalId().getDeviceSubType()
							.equals(SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP)) {

				SBIFingerSlapCaptureInfo captureInfo =
						(SBIFingerSlapCaptureInfo) deviceHelper.getCaptureInfo();

				SBIFingerSlapBioExceptionInfo bioExceptionInfo =
						(SBIFingerSlapBioExceptionInfo)
								deviceHelper.getCaptureInfo()
										.getBioExceptionInfo();


				switch (deviceSubId) {

					// ====================================================
					// LEFT SLAP
					// ====================================================
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT:

						// ---------------- LEFT INDEX ----------------
						if (bioExceptionInfo.getChkMissingLeftIndex()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueLI() != null
									&& captureInfo.getBioValueLI().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_LEFT_INDEX,
										captureInfo.getBioValueLI(),
										captureInfo.getCaptureScoreLI(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}


						// ---------------- LEFT MIDDLE ----------------
						if (bioExceptionInfo.getChkMissingLeftMiddle()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueLM() != null
									&& captureInfo.getBioValueLM().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_LEFT_MIDDLE,
										captureInfo.getBioValueLM(),
										captureInfo.getCaptureScoreLM(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}


						// ---------------- LEFT RING ----------------
						if (bioExceptionInfo.getChkMissingLeftRing()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueLR() != null
									&& captureInfo.getBioValueLR().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_LEFT_RING,
										captureInfo.getBioValueLR(),
										captureInfo.getCaptureScoreLR(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}


						// ---------------- LEFT LITTLE ----------------
						if (bioExceptionInfo.getChkMissingLeftLittle()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueLL() != null
									&& captureInfo.getBioValueLL().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_LEFT_LITTLE,
										captureInfo.getBioValueLL(),
										captureInfo.getCaptureScoreLL(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}

						break;


					// ====================================================
					// RIGHT SLAP
					// ====================================================
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT:

						// ---------------- RIGHT INDEX ----------------
						if (bioExceptionInfo.getChkMissingRightIndex()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueRI() != null
									&& captureInfo.getBioValueRI().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_RIGHT_INDEX,
										captureInfo.getBioValueRI(),
										captureInfo.getCaptureScoreRI(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}


						// ---------------- RIGHT MIDDLE ----------------
						if (bioExceptionInfo.getChkMissingRightMiddle()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueRM() != null
									&& captureInfo.getBioValueRM().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_RIGHT_MIDDLE,
										captureInfo.getBioValueRM(),
										captureInfo.getCaptureScoreRM(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}


						// ---------------- RIGHT RING ----------------
						if (bioExceptionInfo.getChkMissingRightRing()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueRR() != null
									&& captureInfo.getBioValueRR().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_RIGHT_RING,
										captureInfo.getBioValueRR(),
										captureInfo.getCaptureScoreRR(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}


						// ---------------- RIGHT LITTLE ----------------
						if (bioExceptionInfo.getChkMissingRightLittle()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueRL() != null
									&& captureInfo.getBioValueRL().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_RIGHT_LITTLE,
										captureInfo.getBioValueRL(),
										captureInfo.getCaptureScoreRL(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}

						break;


					// ====================================================
					// TWO THUMBS
					// ====================================================
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_THUMB:

						// ---------------- LEFT THUMB ----------------
						if (bioExceptionInfo.getChkMissingLeftThumb()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueLT() != null
									&& captureInfo.getBioValueLT().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_LEFT_THUMB,
										captureInfo.getBioValueLT(),
										captureInfo.getCaptureScoreLT(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}


						// ---------------- RIGHT THUMB ----------------
						if (bioExceptionInfo.getChkMissingRightThumb()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueRT() != null
									&& captureInfo.getBioValueRT().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_RIGHT_THUMB,
										captureInfo.getBioValueRT(),
										captureInfo.getCaptureScoreRT(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}

						break;


					// ====================================================
					// INDIVIDUAL LEFT INDEX
					// ====================================================
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_INDEX:

						if (bioExceptionInfo.getChkMissingLeftIndex()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueLI() != null
									&& captureInfo.getBioValueLI().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_LEFT_INDEX,
										captureInfo.getBioValueLI(),
										captureInfo.getCaptureScoreLI(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}

						break;


					// ====================================================
					// INDIVIDUAL RIGHT INDEX
					// ====================================================
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_INDEX:

						if (bioExceptionInfo.getChkMissingRightIndex()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueRI() != null
									&& captureInfo.getBioValueRI().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_RIGHT_INDEX,
										captureInfo.getBioValueRI(),
										captureInfo.getCaptureScoreRI(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}

						break;


					// ====================================================
					// INDIVIDUAL LEFT MIDDLE
					// ====================================================
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_MIDDLE:

						if (bioExceptionInfo.getChkMissingLeftMiddle()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueLM() != null
									&& captureInfo.getBioValueLM().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_LEFT_MIDDLE,
										captureInfo.getBioValueLM(),
										captureInfo.getCaptureScoreLM(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}

						break;


					// ====================================================
					// INDIVIDUAL RIGHT MIDDLE
					// ====================================================
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_MIDDLE:

						if (bioExceptionInfo.getChkMissingRightMiddle()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueRM() != null
									&& captureInfo.getBioValueRM().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_RIGHT_MIDDLE,
										captureInfo.getBioValueRM(),
										captureInfo.getCaptureScoreRM(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}

						break;


					// ====================================================
					// INDIVIDUAL LEFT RING
					// ====================================================
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_RING:

						if (bioExceptionInfo.getChkMissingLeftRing()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueLR() != null
									&& captureInfo.getBioValueLR().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_LEFT_RING,
										captureInfo.getBioValueLR(),
										captureInfo.getCaptureScoreLR(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}

						break;


					// ====================================================
					// INDIVIDUAL RIGHT RING
					// ====================================================
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_RING:

						if (bioExceptionInfo.getChkMissingRightRing()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueRR() != null
									&& captureInfo.getBioValueRR().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_RIGHT_RING,
										captureInfo.getBioValueRR(),
										captureInfo.getCaptureScoreRR(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}

						break;


					// ====================================================
					// INDIVIDUAL LEFT LITTLE
					// ====================================================
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_LITTLE:

						if (bioExceptionInfo.getChkMissingLeftLittle()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueLL() != null
									&& captureInfo.getBioValueLL().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_LEFT_LITTLE,
										captureInfo.getBioValueLL(),
										captureInfo.getCaptureScoreLL(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}

						break;


					// ====================================================
					// INDIVIDUAL RIGHT LITTLE
					// ====================================================
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_LITTLE:

						if (bioExceptionInfo.getChkMissingRightLittle()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueRL() != null
									&& captureInfo.getBioValueRL().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_RIGHT_LITTLE,
										captureInfo.getBioValueRL(),
										captureInfo.getCaptureScoreRL(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}

						break;


					// ====================================================
					// INDIVIDUAL LEFT THUMB
					// ====================================================
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_LEFT_THUMB:

						if (bioExceptionInfo.getChkMissingLeftThumb()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueLT() != null
									&& captureInfo.getBioValueLT().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_LEFT_THUMB,
										captureInfo.getBioValueLT(),
										captureInfo.getCaptureScoreLT(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}

						break;


					// ====================================================
					// INDIVIDUAL RIGHT THUMB
					// ====================================================
					case SBIConstant.DEVICE_FINGER_SLAP_SUB_TYPE_ID_RIGHT_THUMB:

						if (bioExceptionInfo.getChkMissingRightThumb()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueRT() != null
									&& captureInfo.getBioValueRT().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_RIGHT_THUMB,
										captureInfo.getBioValueRT(),
										captureInfo.getCaptureScoreRT(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}

						break;


					default:

						LOGGER.error(
								"Unsupported Finger deviceSubId :: "
										+ deviceSubId);

						break;
				}
			}


			// ============================================================
			// IRIS DOUBLE
			// ============================================================
			else if (deviceHelper.getDigitalId().getType()
					.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS)
					&&
					deviceHelper.getDigitalId().getDeviceSubType()
							.equals(SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_DOUBLE)) {

				SBIIrisDoubleCaptureInfo captureInfo =
						(SBIIrisDoubleCaptureInfo) deviceHelper.getCaptureInfo();

				SBIIrisDoubleBioExceptionInfo bioExceptionInfo =
						(SBIIrisDoubleBioExceptionInfo)
								deviceHelper.getCaptureInfo()
										.getBioExceptionInfo();


				switch (deviceSubId) {

					// ---------------- LEFT IRIS ----------------
					case SBIConstant.DEVICE_IRIS_DOUBLE_SUB_TYPE_ID_LEFT:

						if (bioExceptionInfo.getChkMissingLeftIris()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueLI() != null
									&& captureInfo.getBioValueLI().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_LEFT_IRIS,
										captureInfo.getBioValueLI(),
										captureInfo.getCaptureScoreLI(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}

						break;


					// ---------------- RIGHT IRIS ----------------
					case SBIConstant.DEVICE_IRIS_DOUBLE_SUB_TYPE_ID_RIGHT:

						if (bioExceptionInfo.getChkMissingRightIris()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueRI() != null
									&& captureInfo.getBioValueRI().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_RIGHT_IRIS,
										captureInfo.getBioValueRI(),
										captureInfo.getCaptureScoreRI(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}

						break;


					// ---------------- BOTH IRIS ----------------
					case SBIConstant.DEVICE_IRIS_DOUBLE_SUB_TYPE_ID_BOTH:

						if (bioExceptionInfo.getChkMissingLeftIris()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueLI() != null
									&& captureInfo.getBioValueLI().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_LEFT_IRIS,
										captureInfo.getBioValueLI(),
										captureInfo.getCaptureScoreLI(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}


						if (bioExceptionInfo.getChkMissingRightIris()
								== SBICheckState.Unchecked) {

							if (captureInfo.getBioValueRI() != null
									&& captureInfo.getBioValueRI().length() > 0) {

								BioMetricsDto bioDto = getBiometricData(
										transactionId,
										requestObject,
										deviceHelper,
										previousHash,
										bioType,
										SBIConstant.BIO_NAME_RIGHT_IRIS,
										captureInfo.getBioValueRI(),
										captureInfo.getCaptureScoreRI(),
										requestScore,
										"",
										"0",
										isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}

							} else {

								BioMetricsDto bioDto =
										getBiometricErrorData(
												lang,
												specVersion,
												isForAuthenication);

								if (bioDto != null) {
									biometrics.add(bioDto);
									previousHash = bioDto.getHash();
								}
							}
						}

						break;


					default:

						LOGGER.error(
								"Unsupported Iris deviceSubId :: "
										+ deviceSubId);

						break;
				}
			}


			// ============================================================
			// FACE
			// ============================================================
			else if (deviceHelper.getDigitalId().getType()
					.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE)
					&&
					deviceHelper.getDigitalId().getDeviceSubType()
							.equals(SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE)) {

				SBIFaceCaptureInfo captureInfo =
						(SBIFaceCaptureInfo) deviceHelper.getCaptureInfo();

				boolean isExceptionPhoto = false;

				if (bioExceptions != null
						&& bioExceptions.length > 0) {

					isExceptionPhoto = true;
				}


				if (!isExceptionPhoto) {

					if (captureInfo.getBioValueFace() != null
							&& captureInfo.getBioValueFace().length() > 0) {

						BioMetricsDto bioDto = getBiometricData(
								transactionId,
								requestObject,
								deviceHelper,
								previousHash,
								bioType,
								null,
								captureInfo.getBioValueFace(),
								captureInfo.getCaptureScoreFace(),
								requestScore,
								"",
								"0",
								isForAuthenication);

						if (bioDto != null) {
							biometrics.add(bioDto);
							previousHash = bioDto.getHash();
						}

					} else {

						BioMetricsDto bioDto =
								getBiometricErrorData(
										lang,
										specVersion,
										isForAuthenication);

						if (bioDto != null) {
							biometrics.add(bioDto);
							previousHash = bioDto.getHash();
						}
					}

				} else {

					if (captureInfo.getBioValueExceptionPhoto() != null
							&& captureInfo.getBioValueExceptionPhoto().length() > 0) {

						BioMetricsDto bioDto = getBiometricData(
								transactionId,
								requestObject,
								deviceHelper,
								previousHash,
								bioType,
								null,
								captureInfo.getBioValueExceptionPhoto(),
								captureInfo.getCaptureScoreFace(),
								requestScore,
								"",
								"0",
								isForAuthenication);

						if (bioDto != null) {
							biometrics.add(bioDto);
							previousHash = bioDto.getHash();
						}

					} else {

						BioMetricsDto bioDto =
								getBiometricErrorData(
										lang,
										specVersion,
										isForAuthenication);

						if (bioDto != null) {
							biometrics.add(bioDto);
							previousHash = bioDto.getHash();
						}
					}
				}
			}
		}


		// ================================================================
		// AUTHENTICATION
		// ================================================================
		else if (isForAuthenication) {

			SBIBioSubTypeInfo bioSubTypeInfo =
					new SBIBioSubTypeInfo();

			bioSubTypeInfo.initBioSubType(bioSubType);


			// ============================================================
			// FINGER SINGLE
			// ============================================================
			if (deviceHelper.getDigitalId().getType()
					.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER)
					&&
					deviceHelper.getDigitalId().getDeviceSubType()
							.equals(SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SINGLE)) {

				SBIFingerSingleCaptureInfo captureInfo =
						(SBIFingerSingleCaptureInfo)
								deviceHelper.getCaptureInfo();


				if (deviceSubId ==
						SBIConstant.DEVICE_FINGER_SINGLE_SUB_TYPE_ID) {

					HashMap<String, String> biometricData =
							captureInfo.getBiometricData();


					if (biometricData != null
							&& biometricData.size() > 0) {

						int bioCounter = 0;


						for (Map.Entry<String, String> pair
								: biometricData.entrySet()) {

							if (bioCounter >= bioCount) {
								break;
							}


							// ------------------------------------------------
							// LEFT INDEX
							// ------------------------------------------------
							if ((bioSubTypeInfo.getChkUnknown()
									== SBICheckState.Checked
									||
									bioSubTypeInfo.getChkLeftIndex()
											== SBICheckState.Checked)
									&&
									pair.getKey().equals(
											SBIConstant.BIO_NAME_LEFT_INDEX)) {

								String bioData = pair.getValue();

								if (bioData != null
										&& bioData.length() > 0) {

									String bioName =
											bioSubTypeInfo.getChkLeftIndex()
													== SBICheckState.Checked
													? SBIConstant.BIO_NAME_LEFT_INDEX
													: SBIConstant.BIO_NAME_UNKNOWN;

									BioMetricsDto bioDto =
											getBiometricData(
													transactionId,
													requestObject,
													deviceHelper,
													previousHash,
													bioType,
													bioName,
													bioData,
													captureInfo.getCaptureScoreLI(),
													requestScore,
													"",
													"0",
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}

								} else {

									BioMetricsDto bioDto =
											getBiometricErrorData(
													lang,
													specVersion,
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}
								}

								bioCounter++;
							}


							// ------------------------------------------------
							// LEFT MIDDLE
							// ------------------------------------------------
							if ((bioSubTypeInfo.getChkUnknown()
									== SBICheckState.Checked
									||
									bioSubTypeInfo.getChkLeftMiddle()
											== SBICheckState.Checked)
									&&
									pair.getKey().equals(
											SBIConstant.BIO_NAME_LEFT_MIDDLE)) {

								String bioData = pair.getValue();

								if (bioData != null
										&& bioData.length() > 0) {

									String bioName =
											bioSubTypeInfo.getChkLeftMiddle()
													== SBICheckState.Checked
													? SBIConstant.BIO_NAME_LEFT_MIDDLE
													: SBIConstant.BIO_NAME_UNKNOWN;

									BioMetricsDto bioDto =
											getBiometricData(
													transactionId,
													requestObject,
													deviceHelper,
													previousHash,
													bioType,
													bioName,
													bioData,
													captureInfo.getCaptureScoreLM(),
													requestScore,
													"",
													"0",
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}

								} else {

									BioMetricsDto bioDto =
											getBiometricErrorData(
													lang,
													specVersion,
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}
								}

								bioCounter++;
							}


							// ------------------------------------------------
							// LEFT RING
							// ------------------------------------------------
							if ((bioSubTypeInfo.getChkUnknown()
									== SBICheckState.Checked
									||
									bioSubTypeInfo.getChkLeftRing()
											== SBICheckState.Checked)
									&&
									pair.getKey().equals(
											SBIConstant.BIO_NAME_LEFT_RING)) {

								String bioData = pair.getValue();

								if (bioData != null
										&& bioData.length() > 0) {

									String bioName =
											bioSubTypeInfo.getChkLeftRing()
													== SBICheckState.Checked
													? SBIConstant.BIO_NAME_LEFT_RING
													: SBIConstant.BIO_NAME_UNKNOWN;

									BioMetricsDto bioDto =
											getBiometricData(
													transactionId,
													requestObject,
													deviceHelper,
													previousHash,
													bioType,
													bioName,
													bioData,
													captureInfo.getCaptureScoreLR(),
													requestScore,
													"",
													"0",
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}

								} else {

									BioMetricsDto bioDto =
											getBiometricErrorData(
													lang,
													specVersion,
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}
								}

								bioCounter++;
							}


							// ------------------------------------------------
							// LEFT LITTLE
							// ------------------------------------------------
							if ((bioSubTypeInfo.getChkUnknown()
									== SBICheckState.Checked
									||
									bioSubTypeInfo.getChkLeftLittle()
											== SBICheckState.Checked)
									&&
									pair.getKey().equals(
											SBIConstant.BIO_NAME_LEFT_LITTLE)) {

								String bioData = pair.getValue();

								if (bioData != null
										&& bioData.length() > 0) {

									String bioName =
											bioSubTypeInfo.getChkLeftLittle()
													== SBICheckState.Checked
													? SBIConstant.BIO_NAME_LEFT_LITTLE
													: SBIConstant.BIO_NAME_UNKNOWN;

									BioMetricsDto bioDto =
											getBiometricData(
													transactionId,
													requestObject,
													deviceHelper,
													previousHash,
													bioType,
													bioName,
													bioData,
													captureInfo.getCaptureScoreLL(),
													requestScore,
													"",
													"0",
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}

								} else {

									BioMetricsDto bioDto =
											getBiometricErrorData(
													lang,
													specVersion,
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}
								}

								bioCounter++;
							}


							// ------------------------------------------------
							// RIGHT INDEX
							// ------------------------------------------------
							if ((bioSubTypeInfo.getChkUnknown()
									== SBICheckState.Checked
									||
									bioSubTypeInfo.getChkRightIndex()
											== SBICheckState.Checked)
									&&
									pair.getKey().equals(
											SBIConstant.BIO_NAME_RIGHT_INDEX)) {

								String bioData = pair.getValue();

								if (bioData != null
										&& bioData.length() > 0) {

									String bioName =
											bioSubTypeInfo.getChkRightIndex()
													== SBICheckState.Checked
													? SBIConstant.BIO_NAME_RIGHT_INDEX
													: SBIConstant.BIO_NAME_UNKNOWN;

									BioMetricsDto bioDto =
											getBiometricData(
													transactionId,
													requestObject,
													deviceHelper,
													previousHash,
													bioType,
													bioName,
													bioData,
													captureInfo.getCaptureScoreRI(),
													requestScore,
													"",
													"0",
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}

								} else {

									BioMetricsDto bioDto =
											getBiometricErrorData(
													lang,
													specVersion,
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}
								}

								bioCounter++;
							}


							// ------------------------------------------------
							// RIGHT MIDDLE
							// ------------------------------------------------
							if ((bioSubTypeInfo.getChkUnknown()
									== SBICheckState.Checked
									||
									bioSubTypeInfo.getChkRightMiddle()
											== SBICheckState.Checked)
									&&
									pair.getKey().equals(
											SBIConstant.BIO_NAME_RIGHT_MIDDLE)) {

								String bioData = pair.getValue();

								if (bioData != null
										&& bioData.length() > 0) {

									String bioName =
											bioSubTypeInfo.getChkRightMiddle()
													== SBICheckState.Checked
													? SBIConstant.BIO_NAME_RIGHT_MIDDLE
													: SBIConstant.BIO_NAME_UNKNOWN;

									BioMetricsDto bioDto =
											getBiometricData(
													transactionId,
													requestObject,
													deviceHelper,
													previousHash,
													bioType,
													bioName,
													bioData,
													captureInfo.getCaptureScoreRM(),
													requestScore,
													"",
													"0",
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}

								} else {

									BioMetricsDto bioDto =
											getBiometricErrorData(
													lang,
													specVersion,
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}
								}

								bioCounter++;
							}


							// ------------------------------------------------
							// RIGHT RING
							// ------------------------------------------------
							if ((bioSubTypeInfo.getChkUnknown()
									== SBICheckState.Checked
									||
									bioSubTypeInfo.getChkRightRing()
											== SBICheckState.Checked)
									&&
									pair.getKey().equals(
											SBIConstant.BIO_NAME_RIGHT_RING)) {

								String bioData = pair.getValue();

								if (bioData != null
										&& bioData.length() > 0) {

									String bioName =
											bioSubTypeInfo.getChkRightRing()
													== SBICheckState.Checked
													? SBIConstant.BIO_NAME_RIGHT_RING
													: SBIConstant.BIO_NAME_UNKNOWN;

									BioMetricsDto bioDto =
											getBiometricData(
													transactionId,
													requestObject,
													deviceHelper,
													previousHash,
													bioType,
													bioName,
													bioData,
													captureInfo.getCaptureScoreRR(),
													requestScore,
													"",
													"0",
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}

								} else {

									BioMetricsDto bioDto =
											getBiometricErrorData(
													lang,
													specVersion,
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}
								}

								bioCounter++;
							}


							// ------------------------------------------------
							// RIGHT LITTLE
							// ------------------------------------------------
							if ((bioSubTypeInfo.getChkUnknown()
									== SBICheckState.Checked
									||
									bioSubTypeInfo.getChkRightLittle()
											== SBICheckState.Checked)
									&&
									pair.getKey().equals(
											SBIConstant.BIO_NAME_RIGHT_LITTLE)) {

								String bioData = pair.getValue();

								if (bioData != null
										&& bioData.length() > 0) {

									String bioName =
											bioSubTypeInfo.getChkRightLittle()
													== SBICheckState.Checked
													? SBIConstant.BIO_NAME_RIGHT_LITTLE
													: SBIConstant.BIO_NAME_UNKNOWN;

									BioMetricsDto bioDto =
											getBiometricData(
													transactionId,
													requestObject,
													deviceHelper,
													previousHash,
													bioType,
													bioName,
													bioData,
													captureInfo.getCaptureScoreRL(),
													requestScore,
													"",
													"0",
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}

								} else {

									BioMetricsDto bioDto =
											getBiometricErrorData(
													lang,
													specVersion,
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}
								}

								bioCounter++;
							}


							// ------------------------------------------------
							// LEFT THUMB
							// ------------------------------------------------
							if ((bioSubTypeInfo.getChkUnknown()
									== SBICheckState.Checked
									||
									bioSubTypeInfo.getChkLeftThumb()
											== SBICheckState.Checked)
									&&
									pair.getKey().equals(
											SBIConstant.BIO_NAME_LEFT_THUMB)) {

								String bioData = pair.getValue();

								if (bioData != null
										&& bioData.length() > 0) {

									String bioName =
											bioSubTypeInfo.getChkLeftThumb()
													== SBICheckState.Checked
													? SBIConstant.BIO_NAME_LEFT_THUMB
													: SBIConstant.BIO_NAME_UNKNOWN;

									BioMetricsDto bioDto =
											getBiometricData(
													transactionId,
													requestObject,
													deviceHelper,
													previousHash,
													bioType,
													bioName,
													bioData,
													captureInfo.getCaptureScoreLT(),
													requestScore,
													"",
													"0",
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}

								} else {

									BioMetricsDto bioDto =
											getBiometricErrorData(
													lang,
													specVersion,
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}
								}

								bioCounter++;
							}


							// ------------------------------------------------
							// RIGHT THUMB
							// ------------------------------------------------
							if ((bioSubTypeInfo.getChkUnknown()
									== SBICheckState.Checked
									||
									bioSubTypeInfo.getChkRightThumb()
											== SBICheckState.Checked)
									&&
									pair.getKey().equals(
											SBIConstant.BIO_NAME_RIGHT_THUMB)) {

								String bioData = pair.getValue();

								if (bioData != null
										&& bioData.length() > 0) {

									String bioName =
											bioSubTypeInfo.getChkRightThumb()
													== SBICheckState.Checked
													? SBIConstant.BIO_NAME_RIGHT_THUMB
													: SBIConstant.BIO_NAME_UNKNOWN;

									BioMetricsDto bioDto =
											getBiometricData(
													transactionId,
													requestObject,
													deviceHelper,
													previousHash,
													bioType,
													bioName,
													bioData,
													captureInfo.getCaptureScoreRT(),
													requestScore,
													"",
													"0",
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}

								} else {

									BioMetricsDto bioDto =
											getBiometricErrorData(
													lang,
													specVersion,
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}
								}

								bioCounter++;
							}
						}

					} else {

						BioMetricsDto bioDto =
								getBiometricErrorData(
										lang,
										specVersion,
										isForAuthenication);

						if (bioDto != null) {
							biometrics.add(bioDto);
							previousHash = bioDto.getHash();
						}
					}
				}
			}


			// ============================================================
			// IRIS SINGLE
			// ============================================================
			else if (deviceHelper.getDigitalId().getType()
					.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS)
					&&
					deviceHelper.getDigitalId().getDeviceSubType()
							.equals(SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_SINGLE)) {

				SBIIrisSingleCaptureInfo captureInfo =
						(SBIIrisSingleCaptureInfo)
								deviceHelper.getCaptureInfo();

				SBIIrisSingleBioExceptionInfo bioExceptionInfo =
						(SBIIrisSingleBioExceptionInfo)
								deviceHelper.getCaptureInfo()
										.getBioExceptionInfo();


				if (deviceSubId ==
						SBIConstant.DEVICE_IRIS_SINGLE_SUB_TYPE_ID) {

					HashMap<String, String> biometricData =
							captureInfo.getBiometricData();


					if (biometricData != null
							&& biometricData.size() > 0) {

						int bioCounter = 0;


						for (Map.Entry<String, String> pair
								: biometricData.entrySet()) {

							if (bioCounter >= bioCount) {
								break;
							}


							// ------------------------------------------------
							// LEFT IRIS
							// ------------------------------------------------
							if ((bioSubTypeInfo.getChkUnknown()
									== SBICheckState.Checked
									||
									bioSubTypeInfo.getChkLeftIris()
											== SBICheckState.Checked)
									&&
									pair.getKey().equals(
											SBIConstant.BIO_NAME_LEFT_IRIS)) {

								String bioData = pair.getValue();

								if (bioData != null
										&& bioData.length() > 0) {

									String bioName =
											bioSubTypeInfo.getChkLeftIris()
													== SBICheckState.Checked
													? SBIConstant.BIO_NAME_LEFT_IRIS
													: SBIConstant.BIO_NAME_UNKNOWN;

									BioMetricsDto bioDto =
											getBiometricData(
													transactionId,
													requestObject,
													deviceHelper,
													previousHash,
													bioType,
													bioName,
													bioData,
													captureInfo.getCaptureScoreLI(),
													requestScore,
													"",
													"0",
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}

								} else {

									BioMetricsDto bioDto =
											getBiometricErrorData(
													lang,
													specVersion,
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}
								}

								bioCounter++;
							}


							// ------------------------------------------------
							// RIGHT IRIS
							// ------------------------------------------------
							if ((bioSubTypeInfo.getChkUnknown()
									== SBICheckState.Checked
									||
									bioSubTypeInfo.getChkRightIris()
											== SBICheckState.Checked)
									&&
									pair.getKey().equals(
											SBIConstant.BIO_NAME_RIGHT_IRIS)) {

								String bioData = pair.getValue();

								if (bioData != null
										&& bioData.length() > 0) {

									String bioName =
											bioSubTypeInfo.getChkRightIris()
													== SBICheckState.Checked
													? SBIConstant.BIO_NAME_RIGHT_IRIS
													: SBIConstant.BIO_NAME_UNKNOWN;

									BioMetricsDto bioDto =
											getBiometricData(
													transactionId,
													requestObject,
													deviceHelper,
													previousHash,
													bioType,
													bioName,
													bioData,
													captureInfo.getCaptureScoreRI(),
													requestScore,
													"",
													"0",
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}

								} else {

									BioMetricsDto bioDto =
											getBiometricErrorData(
													lang,
													specVersion,
													isForAuthenication);

									if (bioDto != null) {
										biometrics.add(bioDto);
										previousHash = bioDto.getHash();
									}
								}

								bioCounter++;
							}
						}

					} else {

						BioMetricsDto bioDto =
								getBiometricErrorData(
										lang,
										specVersion,
										isForAuthenication);

						if (bioDto != null) {
							biometrics.add(bioDto);
							previousHash = bioDto.getHash();
						}
					}
				}
			}


			// ============================================================
			// FACE AUTHENTICATION
			// ============================================================
			else if (deviceHelper.getDigitalId().getType()
					.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE)
					&&
					deviceHelper.getDigitalId().getDeviceSubType()
							.equals(SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE)) {

				SBIFaceCaptureInfo captureInfo =
						(SBIFaceCaptureInfo)
								deviceHelper.getCaptureInfo();

				String bioData =
						captureInfo.getBiometricForBioSubType(
								SBIConstant.BIO_NAME_UNKNOWN);


				if (bioData != null
						&& bioData.length() > 0) {

					BioMetricsDto bioDto = getBiometricData(
							transactionId,
							requestObject,
							deviceHelper,
							previousHash,
							bioType,
							null,
							bioData,
							captureInfo.getCaptureScoreFace(),
							requestScore,
							"",
							"0",
							isForAuthenication);

					if (bioDto != null) {
						biometrics.add(bioDto);
						previousHash = bioDto.getHash();
					}

				} else {

					BioMetricsDto bioDto =
							getBiometricErrorData(
									lang,
									specVersion,
									isForAuthenication);

					if (bioDto != null) {
						biometrics.add(bioDto);
						previousHash = bioDto.getHash();
					}
				}
			}
		}


		return biometrics;
	}
	private BioMetricsDto getBiometricData(String transactionId, CaptureRequestDto requestObject, SBIDeviceHelper deviceHelper,
	                                       String previousHash, String bioType, String bioSubType, String bioValue,
	                                       int qualityScore, int qualityRequestScore, String lang, String errorCode, boolean isUsedForAuthenication) throws SBIException, JsonGenerationException, JsonMappingException, IOException, DecoderException, NoSuchAlgorithmException {
		DeviceInfo deviceInfo = deviceHelper.getDeviceInfo();

		BioMetricsDto biometric = new BioMetricsDto();
		biometric.setSpecVersion(requestObject.getSpecVersion());

		biometric.setError(new ErrorInfo(errorCode, SBIJsonInfo.getErrorDescription(lang, errorCode)));

		BioMetricsDataDto biometricData = new BioMetricsDataDto();
		biometricData.setDeviceCode(deviceInfo.getDeviceCode());
		biometricData.setDigitalId(deviceInfo.getDigitalId());
		biometricData.setDeviceServiceVersion(deviceInfo.getServiceVersion());
		biometricData.setBioType(bioType);
		biometricData.setBioSubType(bioSubType);

		biometricData.setPurpose(requestObject.getPurpose());
		biometricData.setEnv(requestObject.getEnv());

		if (isUsedForAuthenication)
			biometricData.setDomainUri(requestObject.getDomainUri() + "");

		if (isUsedForAuthenication == false) {
			biometricData.setBioValue(bioValue);
			biometricData.setTimestamp(CryptoUtility.getTimestamp());
		} else {
			try {
				X509Certificate certificate = new JwtUtility().getCertificateToEncryptCaptureBioValue();
				PublicKey publicKey = certificate.getPublicKey();
				Map<String, String> cryptoResult = CryptoUtility.encrypt(publicKey,
						io.mosip.mock.sbi.util.StringHelper.base64UrlDecode(bioValue), transactionId);

				biometricData.setTimestamp(cryptoResult.get("TIMESTAMP"));
				biometricData.setBioValue(cryptoResult.containsKey("ENC_DATA") ?
						cryptoResult.get("ENC_DATA") : null);
				biometric.setSessionKey(cryptoResult.get("ENC_SESSION_KEY"));
				String thumbPrint = toHex(JwtUtility.getCertificateThumbprint(certificate)).replace("-", "").toUpperCase();
				biometric.setThumbprint(thumbPrint);
			} catch (Exception ex) {
				ex.printStackTrace();
				LOGGER.error("getBiometricData :: encrypt :: ", ex);
				throw new SBIException("IDA Biometric encryption Certificate not found", "IDA Biometric encryption Certificate not found", ex);
			}
		}

		biometricData.setRequestedScore(qualityRequestScore + "");
		biometricData.setQualityScore(qualityScore + "");
		biometricData.setTransactionId(transactionId);

		ObjectMapper mapper = new ObjectMapper();
		SerializationConfig config = mapper.getSerializationConfig();
		config.setSerializationInclusion(Inclusion.NON_NULL);
		mapper.setSerializationConfig(config);

		String currentBioData = mapper.writeValueAsString(biometricData);

		//base64 signature of the data block. base64 signature of the hash element
		String dataBlockSignBase64 = deviceHelper.getSignBioMetricsDataDto(deviceHelper.getDeviceType(), deviceHelper.getDeviceSubType(), currentBioData);
		biometric.setData(dataBlockSignBase64);

		byte[] previousBioDataHash = null;
		if (previousHash == null || previousHash.trim().length() == 0) {
			byte[] previousDataByteArr = StringHelper.toUtf8ByteArray("");
			previousBioDataHash = generateHash(previousDataByteArr);
		} else {
			previousBioDataHash = decodeHex(previousHash);
		}
		//instead of BioData, bioValue (before encrytion in case of Capture response) is used for computing the hash.
		byte[] currentDataByteArr = io.mosip.mock.sbi.util.StringHelper.base64UrlDecode(bioValue);
		// Here Byte Array
		byte[] currentBioDataHash = generateHash(currentDataByteArr);
		byte[] finalBioDataHash = new byte[currentBioDataHash.length + previousBioDataHash.length];
		System.arraycopy(previousBioDataHash, 0, finalBioDataHash, 0, previousBioDataHash.length);
		System.arraycopy(currentBioDataHash, 0, finalBioDataHash, previousBioDataHash.length, currentBioDataHash.length);

		biometric.setHash(toHex(generateHash(finalBioDataHash)));

		return biometric;
	}

	public String toHex(byte[] bytes) {
		return Hex.encodeHexString(bytes).toUpperCase();
	}

	private final String HASH_ALGORITHM_NAME = "SHA-256";

	public byte[] generateHash(final byte[] bytes) throws NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance(HASH_ALGORITHM_NAME);
		return messageDigest.digest(bytes);
	}

	public byte[] decodeHex(String hexData) throws DecoderException {
		return Hex.decodeHex(hexData);
	}

	private BioMetricsDto getBiometricErrorData(String lang, String specVersion, boolean isForAuthenication) {
		String errorCode = "701";
		BioMetricsDto biometric = new BioMetricsDto();
		biometric.setSpecVersion(specVersion);
		biometric.setData("");
		biometric.setHash("");
		if (isForAuthenication) {
			errorCode = "801";
			biometric.setSessionKey("");
			biometric.setThumbprint("");
		}

		biometric.setError(new ErrorInfo(errorCode, (SBIJsonInfo.getErrorDescription(lang, errorCode)).trim()));

		return biometric;
	}

	private void renderMainHeaderData(Socket socket) throws IOException {
		writeMainHeader(socket);
	}

	private void writeMainHeader(Socket socket) throws IOException {
		// prepare main header
		byte[] mainHeader = createMainHeader();

		BufferedOutputStream outputStream = new BufferedOutputStream(socket.getOutputStream());
		outputStream.write(mainHeader, 0, mainHeader.length);
		outputStream.flush();
		outputStream.flush();
	}

	private byte[] createMainHeader() {
		String header =
				"HTTP/1.0 200 OK\r\n" +
						"Server: http://" + ApplicationPropertyHelper.getPropertyKeyValue(SBIConstant.SERVER_ADDRESS) + ":" + getPort() + "\r\n" +
						"Access-Control-Allow-Origin:*\r\n" +
						"Connection: close\r\n" +
						"Max-Age: 0\r\n" +
						"Expires: 0\r\n" +
						"Cache-Control: no-cache, private\r\n" +
						"Pragma: no-cache\r\n" +
						"Content-Type: multipart/x-mixed-replace; " +
						"boundary=--BoundaryString\r\n\r\n";

		// using ascii encoder is fine since there is no international character used in this string.
		return header.getBytes(StandardCharsets.US_ASCII);
	}

	private void renderJPGImageData(Socket socket, byte[] image) throws IOException {
		if (image != null && socket != null && !socket.isClosed())
			writeFrame(socket, image);
	}

	private void writeFrame(Socket socket, byte[] image) throws IOException {
		// prepare image data
		byte[] imageInByte = image;

		// prepare header
		byte[] header = createHeader(imageInByte.length);
		// prepare footer
		byte[] footer = createFooter();

		BufferedOutputStream outputStream = new BufferedOutputStream(socket.getOutputStream());
		// Start writing data
		outputStream.write(header, 0, header.length);
		outputStream.write(imageInByte, 0, imageInByte.length);
		outputStream.write(footer, 0, footer.length);
		outputStream.flush();
		outputStream.flush();
	}

	private byte[] createHeader(int length) {
		String header =
				"--BoundaryString\r\n" +
						"Access-Control-Allow-Origin:*\r\n" +
						"Content-Type:image/jpeg\r\n" +
						"Content-Length:" + length + "\r\n\r\n"; // there are always 2 new line character before the actual data

		// using ascii encoder is fine since there is no international character used in this string.
		return header.getBytes(StandardCharsets.US_ASCII);
	}

	public byte[] createFooter() {
		return "\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
	}

	/*
	private SBIDeviceHelper getDeviceHelperForDeviceId(SBIMockService mockService, String deviceId) {

		SBIDeviceHelper deviceHelper = null;

		deviceHelper = (SBIFaceHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE);
		deviceHelper.initDeviceDetails();
		if (deviceHelper.getDeviceInfo() != null && deviceHelper.getDeviceInfo().getDeviceId().equals(deviceId)) {
			return deviceHelper;
		}

		switch (mockService.getPurpose()) {
			case SBIConstant.PURPOSE_REGISTRATION:
				deviceHelper = (SBIFingerSlapHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP);
				deviceHelper.initDeviceDetails();
				if (deviceHelper.getDeviceInfo() != null && deviceHelper.getDeviceInfo().getDeviceId().equals(deviceId)) {
					return deviceHelper;
				}

				deviceHelper = (SBIIrisDoubleHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_DOUBLE);
				deviceHelper.initDeviceDetails();
				if (deviceHelper.getDeviceInfo() != null && deviceHelper.getDeviceInfo().getDeviceId().equals(deviceId)) {
					return deviceHelper;
				}
				break;
			case SBIConstant.PURPOSE_AUTH:
				deviceHelper = (SBIFingerSingleHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SINGLE);
				deviceHelper.initDeviceDetails();
				if (deviceHelper.getDeviceInfo() != null && deviceHelper.getDeviceInfo().getDeviceId().equals(deviceId)) {
					return deviceHelper;
				}

				deviceHelper = (SBIIrisSingleHelper) mockService.getDeviceHelper(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS + "_" + SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_SINGLE);
				deviceHelper.initDeviceDetails();
				if (deviceHelper.getDeviceInfo() != null && deviceHelper.getDeviceInfo().getDeviceId().equals(deviceId)) {
					return deviceHelper;
				}
				break;
		}

		return null;
	}
*/
	private SBIDeviceHelper getDeviceHelperForDeviceId(
			SBIMockService mockService, String deviceId) {

		SBIDeviceHelper deviceHelper = null;

		LOGGER.info("========== DEVICE HELPER SEARCH START ==========");
		LOGGER.info("Requested deviceId :: " + deviceId);
		LOGGER.info("Requested purpose :: " + mockService.getPurpose());

		/*
		 * =====================================================
		 * 1. FACE
		 * =====================================================
		 */
		deviceHelper = mockService.getDeviceHelper(
				SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE + "_"
						+ SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FACE);

		if (deviceHelper != null) {

			deviceHelper.initDeviceDetails();

			LOGGER.info("Checking FACE");
			LOGGER.info("FACE deviceId :: "
					+ (deviceHelper.getDeviceInfo() != null
					? deviceHelper.getDeviceInfo().getDeviceId()
					: "NULL"));

			if (deviceHelper.getDeviceInfo() != null
					&& deviceId.equals(deviceHelper.getDeviceInfo().getDeviceId())) {

				LOGGER.info("FACE DEVICE FOUND :: " + deviceId);
				LOGGER.info("========== DEVICE HELPER SEARCH END ==========");
				return deviceHelper;
			}
		}

		/*
		 * =====================================================
		 * REGISTRATION
		 * =====================================================
		 */
		if (SBIConstant.PURPOSE_REGISTRATION.equalsIgnoreCase(
				mockService.getPurpose())) {

			/*
			 * -------------------------------------------------
			 * 2. FINGER SLAP
			 * -------------------------------------------------
			 */
			deviceHelper = mockService.getDeviceHelper(
					SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER + "_"
							+ SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SLAP);

			if (deviceHelper != null) {

				deviceHelper.initDeviceDetails();

				LOGGER.info("Checking FINGER SLAP");
				LOGGER.info("Finger Slap deviceId :: "
						+ (deviceHelper.getDeviceInfo() != null
						? deviceHelper.getDeviceInfo().getDeviceId()
						: "NULL"));

				if (deviceHelper.getDeviceInfo() != null
						&& deviceId.equals(
						deviceHelper.getDeviceInfo().getDeviceId())) {

					LOGGER.info("FINGER SLAP DEVICE FOUND :: " + deviceId);
					LOGGER.info("========== DEVICE HELPER SEARCH END ==========");
					return deviceHelper;
				}
			}

			/*
			 * -------------------------------------------------
			 * 3. FINGER SINGLE
			 *
			 * IMPORTANT:
			 * Your deviceId = 4 is expected here.
			 * -------------------------------------------------
			 */

			/*
			 * -------------------------------------------------
			 * 4. IRIS DOUBLE
			 * -------------------------------------------------
			 */
			deviceHelper = mockService.getDeviceHelper(
					SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS + "_"
							+ SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_DOUBLE);

			if (deviceHelper != null) {

				deviceHelper.initDeviceDetails();

				LOGGER.info("Checking IRIS DOUBLE");
				LOGGER.info("Iris Double deviceId :: "
						+ (deviceHelper.getDeviceInfo() != null
						? deviceHelper.getDeviceInfo().getDeviceId()
						: "NULL"));

				if (deviceHelper.getDeviceInfo() != null
						&& deviceId.equals(
						deviceHelper.getDeviceInfo().getDeviceId())) {

					LOGGER.info("IRIS DOUBLE DEVICE FOUND :: " + deviceId);
					LOGGER.info("========== DEVICE HELPER SEARCH END ==========");
					return deviceHelper;
				}
			}
		}

		/*
		 * =====================================================
		 * AUTHENTICATION
		 * =====================================================
		 */
		else if (SBIConstant.PURPOSE_AUTH.equalsIgnoreCase(
				mockService.getPurpose())) {

			/*
			 * -------------------------------------------------
			 * 5. FINGER SINGLE
			 * -------------------------------------------------
			 */
			deviceHelper = mockService.getDeviceHelper(
					SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER + "_"
							+ SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_FINGER_SINGLE);

			if (deviceHelper != null) {

				deviceHelper.initDeviceDetails();

				LOGGER.info("Checking AUTH FINGER SINGLE");
				LOGGER.info("Finger Single deviceId :: "
						+ (deviceHelper.getDeviceInfo() != null
						? deviceHelper.getDeviceInfo().getDeviceId()
						: "NULL"));

				if (deviceHelper.getDeviceInfo() != null
						&& deviceId.equals(
						deviceHelper.getDeviceInfo().getDeviceId())) {

					LOGGER.info("AUTH FINGER SINGLE DEVICE FOUND :: " + deviceId);
					LOGGER.info("========== DEVICE HELPER SEARCH END ==========");
					return deviceHelper;
				}
			}

			/*
			 * -------------------------------------------------
			 * 6. IRIS SINGLE
			 * -------------------------------------------------
			 */
			deviceHelper = mockService.getDeviceHelper(
					SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS + "_"
							+ SBIConstant.MOSIP_BIOMETRIC_SUBTYPE_IRIS_SINGLE);

			if (deviceHelper != null) {

				deviceHelper.initDeviceDetails();

				LOGGER.info("Checking AUTH IRIS SINGLE");
				LOGGER.info("Iris Single deviceId :: "
						+ (deviceHelper.getDeviceInfo() != null
						? deviceHelper.getDeviceInfo().getDeviceId()
						: "NULL"));

				if (deviceHelper.getDeviceInfo() != null
						&& deviceId.equals(
						deviceHelper.getDeviceInfo().getDeviceId())) {

					LOGGER.info("AUTH IRIS SINGLE DEVICE FOUND :: " + deviceId);
					LOGGER.info("========== DEVICE HELPER SEARCH END ==========");
					return deviceHelper;
				}
			}
		}

		LOGGER.error("========== DEVICE HELPER SEARCH FAILED ==========");
		LOGGER.error("No device found for deviceId :: " + deviceId);
		LOGGER.error("Purpose :: " + mockService.getPurpose());
		LOGGER.error("========== DEVICE HELPER SEARCH END ==========");

		return null;
	}

	public Object getRequestJson(String methodVerb) {
		if (getRequest() != null && getRequest().indexOf("{") >= 0) {
			try {
				ObjectMapper mapper = new ObjectMapper();
				if (methodVerb.equalsIgnoreCase(SBIConstant.MOSIP_DISC_VERB))
					return mapper.readValue(getRequest().substring(getRequest().indexOf("{")), DeviceDiscoveryRequestDetail.class);
				if (methodVerb.equalsIgnoreCase(SBIConstant.MOSIP_STREAM_VERB))
					return mapper.readValue(getRequest().substring(getRequest().indexOf("{")), StreamingRequestDetail.class);
				if (methodVerb.equalsIgnoreCase(SBIConstant.MOSIP_RCAPTURE_VERB))
					return mapper.readValue(getRequest().substring(getRequest().indexOf("{")), CaptureRequestDto.class);

				if (methodVerb.equalsIgnoreCase(SBIConstant.MOSIP_ADMIN_API_STATUS))
					return mapper.readValue(getRequest().substring(getRequest().indexOf("{")), StatusRequest.class);
				if (methodVerb.equalsIgnoreCase(SBIConstant.MOSIP_ADMIN_API_SCORE))
					return mapper.readValue(getRequest().substring(getRequest().indexOf("{")), ScoreRequest.class);
				if (methodVerb.equalsIgnoreCase(SBIConstant.MOSIP_ADMIN_API_DELAY))
					return mapper.readValue(getRequest().substring(getRequest().indexOf("{")), DelayRequest.class);
				if (methodVerb.equalsIgnoreCase(SBIConstant.MOSIP_ADMIN_API_PROFILE))
					return mapper.readValue(getRequest().substring(getRequest().indexOf("{")), ProfileRequest.class);

				return null;
			} catch (Exception ex) {
				LOGGER.error("getRequestJson", ex);
				return null;
			}
		} else {
			return null;
		}
	}


	public PublicKey getPublicKeyToEncryptCaptureBioValue() throws Exception {
		String certificate = getPublicKeyFromIDA();
		certificate = trimBeginEnd(certificate);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate x509Certificate = (X509Certificate) cf.generateCertificate(
				new ByteArrayInputStream(Base64.getDecoder().decode(certificate)));

		return x509Certificate.getPublicKey();
	}

	public String getThumbprint() throws Exception {
		String certificate = getPublicKeyFromIDA();
		certificate = trimBeginEnd(certificate);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate x509Certificate = (X509Certificate) cf.generateCertificate(
				new ByteArrayInputStream(Base64.getDecoder().decode(certificate)));
		String thumbprint = CryptoUtil.computeFingerPrint(x509Certificate.getEncoded(), null);

		return thumbprint;
	}

	public String getPublicKeyFromIDA() {
		OkHttpClient client = new OkHttpClient();
		String requestBody = String.format(AUTH_REQ_TEMPLATE,
				ApplicationPropertyHelper.getPropertyKeyValue("mosip.auth.appid"),
				ApplicationPropertyHelper.getPropertyKeyValue("mosip.auth.clientid"),
				ApplicationPropertyHelper.getPropertyKeyValue("mosip.auth.secretkey"),
				DateUtils.getUTCCurrentDateTime());

		MediaType mediaType = MediaType.parse("application/json; charset=utf-8");
		RequestBody body = RequestBody.create(mediaType, requestBody);
		Request request = new Request.Builder()
				.url(ApplicationPropertyHelper.getPropertyKeyValue("mosip.auth.server.url"))
				.post(body)
				.build();
		try {
			Response response = client.newCall(request).execute();
			if (response.isSuccessful()) {
				String authToken = response.header("authorization");

				Request idarequest = new Request.Builder()
						.header("cookie", "Authorization=" + authToken)
						.url(ApplicationPropertyHelper.getPropertyKeyValue("mosip.ida.server.url"))
						.get()
						.build();

				Response idaResponse = new OkHttpClient().newCall(idarequest).execute();
				if (idaResponse.isSuccessful()) {
					JSONObject jsonObject = new JSONObject(idaResponse.body().string());
					jsonObject = jsonObject.getJSONObject("response");
					return jsonObject.getString("certificate");
				}
			}

		} catch (IOException | JSONException e) {
			e.printStackTrace();
		}
		return null;
	}

	private String trimBeginEnd(String pKey) {
		pKey = pKey.replaceAll("-*BEGIN([^-]*)-*(\r?\n)?", "");
		pKey = pKey.replaceAll("-*END([^-]*)-*(\r?\n)?", "");
		pKey = pKey.replaceAll("\\s", "");
		return pKey;
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public String getRequest() {
		return request;
	}

	public void setRequest(String request) {
		this.request = request;
	}

	public static Semaphore getSemaphore() {
		return semaphore;
	}

	public static void setSemaphore(Semaphore semaphore) {
		SBIServiceResponse.semaphore = semaphore;
	}

	private void delay(long millseconds) {
		try {
			Thread.sleep(millseconds);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private boolean isValidBioExceptionValues(String bioType, String[] bioExceptions) {
		if (bioExceptions != null) {
			if (bioType.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER))
				return bioExceptionsListFinger.containsAll(Arrays.asList(bioExceptions));
			else if (bioType.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS))
				return bioExceptionsListIris.containsAll(Arrays.asList(bioExceptions));
			else if (bioType.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE))
				return true;
		}
		return true;
	}

	private boolean isValidBioSubtypeValues(String bioType, String[] bioSubtypes, boolean isCapture) {
		if (bioSubtypes != null) {
			if (bioType.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FINGER))
				return bioSubtypesListFinger.containsAll(Arrays.asList(bioSubtypes));
			else if (bioType.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_IRIS))
				return bioSubtypesListIris.containsAll(Arrays.asList(bioSubtypes));
			else if (bioType.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE))
				return true;
		}
		if (isCapture) {
			if (bioType.equals(SBIConstant.MOSIP_BIOMETRIC_TYPE_FACE))
				return true;
			else
				return false;
		} else
			return true;
	}
}