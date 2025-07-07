package io.mosip.mock.sdk.service;

import java.util.*;

import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

import io.mosip.kernel.biometrics.constant.BiometricType;
import io.mosip.kernel.biometrics.constant.ProcessedLevelType;
import io.mosip.kernel.biometrics.entities.BDBInfo;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.biometrics.entities.BiometricRecord;
import io.mosip.kernel.biometrics.model.Response;
import io.mosip.mock.sdk.constant.ResponseStatus;
import io.mosip.mock.sdk.exceptions.SDKException;

public class ExtractTemplateService extends SDKService {
	private Logger LOGGER = LoggerFactory.getLogger(ExtractTemplateService.class);

	private BiometricRecord sample;
	private List<BiometricType> modalitiesToExtract;

	private ProcessedLevelType[] types = new ProcessedLevelType[] { ProcessedLevelType.INTERMEDIATE,
			ProcessedLevelType.PROCESSED };

	public static final long FORMAT_TYPE_FINGER = 7;
	public static final long FORMAT_TYPE_FINGER_MINUTIAE = 2;
	private String stringVal = "84,53,0,0,0,73,51,-93,-127,61,-102,-39,-84,-67,-29,-5,13,-67,66,-83,38,-67,73,50,-71,61,-124,82,-31,61,15,26,125,-67,94,-63,112,-67,-29,-5,13,61,88,60,94,61,-58,-17,-81,-67,-110,84,26,-67,-22,-128,-96,-68,-29,-5,-115,61,-15,5,-77,61,-22,-128,-96,61,-22,-128,-96,-68,81,-73,-53,-67,-29,-5,13,-67,0,0,0,0,-95,90,9,62,95,-71,-124,61,-22,-128,-96,-67,124,-51,-50,61,88,60,94,60,-73,-19,-10,-68,94,-63,112,61,-73,-19,-10,-68,58,40,-108,-69,-102,-39,-84,61,58,40,-108,61,37,-95,-56,-67,58,40,20,-67,-88,-29,81,-67,15,26,-3,61,-7,-118,69,60,66,-83,-90,-67,15,26,125,61,-80,104,100,61,-7,-118,-59,-69,-73,-19,-10,59,94,-63,112,61,15,26,125,61,-29,-5,13,-67,-102,-39,44,60,-102,-39,-84,-68,-29,3,-6,-67,51,-93,1,61,103,62,23,-66,103,62,-105,61,58,40,-108,-69,-29,-5,13,61,0,0,0,0,81,-73,75,61,94,-63,112,61,-110,84,26,-67,-110,84,26,-67,-110,84,26,61,44,38,-37,61,-73,-19,118,-67,-7,-118,69,-68,81,-73,75,61,58,40,20,60,88,60,94,61,-88,-29,81,-67,-102,-39,44,60,-22,-128,32,-67,-7,-118,69,-69,-102,-39,-84,-68,-29,-5,-115,61,58,40,20,61,66,-83,-90,61,-80,104,100,61,-88,-29,81,-67,-88,-29,-47,-68,-73,-19,-10,59,-73,-19,118,-68,15,26,125,-67,29,28,-74,61,-7,-118,-59,58,-102,-39,-84,60,-7,-118,69,61,-7,-118,-59,-70,-102,-39,-84,60,-7,-118,-59,-70,-7,-118,69,60,-73,-19,118,-68,-117,-49,-121,-68,-29,-5,13,-67,73,50,-71,60,51,-93,-127,-67,-73,-27,-118,61,103,62,23,-66,-117,-49,-121,60,-73,-19,-10,-69,103,62,23,62,-22,-128,32,61,-117,-49,-121,60,-22,-128,-96,-67,-29,-5,13,61,0,0,0,0,-73,-19,118,-67,22,-105,-93,-67,29,28,-74,61,-88,-29,81,61,58,40,20,-67,15,26,-3,-67,58,40,20,60,-66,106,-99,61,58,40,-108,60,-96,94,-65,61,-117,-49,7,61,94,-63,112,61,-29,-5,13,-67,-7,-118,69,60,58,40,-108,-67,-58,-17,-81,61,-102,-39,-84,60,73,50,-71,60,88,60,-34,-68,66,-83,-90,-67,-73,-19,-10,59,36,-99,18,62,51,-93,-127,-67,-1,15,88,-67,-117,-49,-121,60,14,18,-111,61,95,-71,-124,-67,-73,-19,-10,-68,-117,-41,-13,-67,-96,94,63,61,-73,-19,-10,-69,-102,-39,-84,60,-73,-19,-10,59,-29,-5,-115,-67,-88,-29,-47,60,-117,-49,7,-66,88,60,94,-68,7,-107,106,61,-7,-118,69,59,103,62,-105,-67,-88,-29,-47,60,-22,-128,-96,-67,-7,-118,69,61,7,-107,106,61,81,-73,75,61,-1,15,88,-67,-1,15,-40,61,66,-83,38,-67,37,-95,-56,-67,-22,-128,-96,60,-88,-29,81,-67,88,60,94,-67,-117,-49,-121,-67,-117,-49,-121,-68,-66,106,-99,-67,51,-93,1,61,73,50,-71,60,-110,84,26,-67,51,-93,-127,-67,-7,-118,69,59,-66,106,-99,-67,58,40,20,-68,7,-107,-22,-68,66,-83,38,61,-117,-49,7,61,-73,-19,118,60,-102,-39,44,61,-102,-39,44,60,22,-105,-93,-67,-117,-49,-121,-68,-7,-118,69,59,-80,104,100,61,88,56,40,62,-15,5,-77,-67,117,72,-68,-67,-96,94,63,-67,73,46,3,62,-7,-118,-59,59,-15,5,-77,-67,-88,-29,-47,-68,-73,-19,118,-67,-73,-19,118,-68,-117,-41,-13,-67,-80,104,100,-67,-102,-39,-84,-68,-117,-49,-121,-68,-29,-5,13,61,103,62,-105,61,-29,3,-6,61,-22,-128,-96,60,-102,-39,-84,-68,-73,-19,-10,60,73,50,-71,60,-7,-118,-59,-67,0,0,0,0,66,-83,-90,-67,88,60,94,61,-58,-17,-81,61,58,40,20,61,-96,94,-65,-67,-29,3,-6,61,7,-107,-22,-68,-110,84,26,-66,-88,-29,-47,-68,58,40,-108,-68,-66,106,-99,-67,-117,-49,-121,60,-22,-128,-96,-68,7,-107,-22,60,-102,-39,-84,61,-7,-118,69,-68,58,40,-108,59,-7,-118,-59,-69,37,-95,-56,61,73,50,57,-67,58,40,20,61,88,60,-34,-68,-66,106,-99,-67,95,-71,-124,-67,-80,104,100,61,124,-55,24,62,-73,-27,-118,61,37,-95,-56,-67,66,-83,38,-67,-110,84,-102,-67,88,60,-34,60,-73,-19,-10,-67,-117,-49,-121,60,-66,106,-99,-67,117,72,-68,61,66,-83,38,61,-22,-128,-96,60,-73,-19,118,-67,-88,-29,-47,60,95,-71,-124,61,-110,84,26,61,58,40,20,-68,88,60,94,-68,-117,-49,-121,-67,-22,-128,-96,-67,51,-93,-127,61,-73,-19,118,61,124,-51,-50,61,-73,-19,-10,60,-7,-118,69,-69,-96,94,63,61,-73,-19,-10,-67,-102,-39,44,61,-7,-118,69,61,-29,-5,13,-67,0,0,0,0,7,-107,-22,60,-7,-118,-59,-68,66,-83,38,61,-88,-29,81,-67";
	private byte[] template;

	public ExtractTemplateService(Environment env, BiometricRecord sample, List<BiometricType> modalitiesToExtract,
			Map<String, String> flags) {
		super(env, flags);
		this.sample = sample;
		this.modalitiesToExtract = modalitiesToExtract;

		Object[] objValue = Arrays.stream(stringVal.split(",")).toArray();
		List<Byte> byteList = new ArrayList<Byte>();
		Byte[] byteValue = new Byte[objValue.length];
		Arrays.stream(objValue).forEach(val -> byteList.add(Byte.parseByte(val.toString())));
		byteList.toArray(byteValue);
		template = ArrayUtils.toPrimitive(byteValue);
	}

	public Response<BiometricRecord> getExtractTemplateInfo() {
		Long startTime = System.currentTimeMillis();
		ResponseStatus responseStatus = null;
		Response<BiometricRecord> response = new Response<>();
		try {
			if (sample == null || sample.getSegments() == null || sample.getSegments().isEmpty()) {
				responseStatus = ResponseStatus.MISSING_INPUT;
				throw new SDKException(responseStatus.getStatusCode() + "", responseStatus.getStatusMessage());
			}

			if (sample != null)
				LOGGER.info("extractTemplate segment size {}", sample.getSegments().size());

			for (BIR segment : sample.getSegments()) {
				if (!isValidBirData(segment))
					break;

			//	segment.getBirInfo().setPayload(segment.getBdb());

				BDBInfo bdbInfo = segment.getBdbInfo();
				if (bdbInfo != null) {
					// Update the level to processed
					bdbInfo.setLevel(getRandomLevelType());
					if (segment.getBdbInfo().getFormat() != null) {
						String type = segment.getBdbInfo().getFormat().getType();
						// Update the fingerprint image to fingerprint minutiae type
						if (type != null && type.equals(String.valueOf(FORMAT_TYPE_FINGER))) {
							segment.getBdbInfo().getFormat().setType(String.valueOf(FORMAT_TYPE_FINGER_MINUTIAE));
						}
					}
				}

				segment.setBdb(template);
				segment.setSb(null);
				// do actual extraction

				int delayInMs = getDelayTime();
				long sleepTime = delayInMs - (System.currentTimeMillis() - startTime);
				if(sleepTime > 0)
					Thread.sleep(sleepTime);
			}
		} catch (SDKException ex) {
			LOGGER.error("extractTemplate -- error", ex);
			switch (ResponseStatus.fromStatusCode(Integer.parseInt(ex.getErrorCode()))) {
			case INVALID_INPUT:
				response.setStatusCode(ResponseStatus.INVALID_INPUT.getStatusCode());
				response.setStatusMessage(String.format(ResponseStatus.INVALID_INPUT.getStatusMessage(), "sample"));
				response.setResponse(null);
				return response;
			case MISSING_INPUT:
				response.setStatusCode(ResponseStatus.MISSING_INPUT.getStatusCode());
				response.setStatusMessage(String.format(ResponseStatus.MISSING_INPUT.getStatusMessage(), "sample"));
				response.setResponse(null);
				return response;
			case QUALITY_CHECK_FAILED:
				response.setStatusCode(ResponseStatus.QUALITY_CHECK_FAILED.getStatusCode());
				response.setStatusMessage(String.format(ResponseStatus.QUALITY_CHECK_FAILED.getStatusMessage(), ""));
				response.setResponse(null);
				return response;
			case BIOMETRIC_NOT_FOUND_IN_CBEFF:
				response.setStatusCode(ResponseStatus.BIOMETRIC_NOT_FOUND_IN_CBEFF.getStatusCode());
				response.setStatusMessage(
						String.format(ResponseStatus.BIOMETRIC_NOT_FOUND_IN_CBEFF.getStatusMessage(), ""));
				response.setResponse(null);
				return response;
			case MATCHING_OF_BIOMETRIC_DATA_FAILED:
				response.setStatusCode(ResponseStatus.MATCHING_OF_BIOMETRIC_DATA_FAILED.getStatusCode());
				response.setStatusMessage(
						String.format(ResponseStatus.MATCHING_OF_BIOMETRIC_DATA_FAILED.getStatusMessage(), ""));
				response.setResponse(null);
				return response;
			case POOR_DATA_QUALITY:
				response.setStatusCode(ResponseStatus.POOR_DATA_QUALITY.getStatusCode());
				response.setStatusMessage(String.format(ResponseStatus.POOR_DATA_QUALITY.getStatusMessage(), ""));
				response.setResponse(null);
				return response;
			default:
				response.setStatusCode(ResponseStatus.UNKNOWN_ERROR.getStatusCode());
				response.setStatusMessage(String.format(ResponseStatus.UNKNOWN_ERROR.getStatusMessage(), ""));
				response.setResponse(null);
				return response;
			}
		} catch (Exception ex) {
			LOGGER.error("extractTemplate -- error", ex);
			response.setStatusCode(ResponseStatus.UNKNOWN_ERROR.getStatusCode());
			response.setStatusMessage(String.format(ResponseStatus.UNKNOWN_ERROR.getStatusMessage(), ""));
			response.setResponse(null);
			return response;
		}
		response.setStatusCode(ResponseStatus.SUCCESS.getStatusCode());
		response.setResponse(sample);

        return response;
	}

	public ProcessedLevelType getRandomLevelType() {
		int rnd = new Random().nextInt(types.length);
		return types[rnd];
	}
}
