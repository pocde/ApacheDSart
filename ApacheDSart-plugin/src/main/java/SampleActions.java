import com.hp.oo.sdk.content.annotations.Action;
import com.hp.oo.sdk.content.annotations.Output;
import com.hp.oo.sdk.content.annotations.Param;
import com.hp.oo.sdk.content.annotations.Response;
import com.hp.oo.sdk.content.constants.OutputNames;
import com.hp.oo.sdk.content.constants.ResponseNames;
import com.hp.oo.sdk.content.plugin.ActionMetadata.MatchType;
import com.hp.oo.sdk.content.plugin.ActionMetadata.ResponseType;

import java.util.HashMap;
import java.util.Map;

public class SampleActions {

    /**
     * This Action sums two numbers and results in success only if the sum is positive.
     * The description "Adds two numbers" will be imported into the Description field when this action is imported into Studio.
     * The action has two outputs - One containing the actual result, and the other a message.
     * The action has two responses
     *  Success - A success response. Will be chosen when the field "result" (From the return map) will be greater than or equal to "0"
     *  Failure - An error response. Will be chosen when the field "result" (From the return map) will be less than "0"
     *
     * @param x The first number. @Param("op1") will make x's name in OO (Studio and central) be "op1"
     * @param y The second number. @Param("op2") will make y's name in OO (Studio and central) be "op2"
     */
    @Action(name = "checkPositiveSum",
            description = "Adds two numbers",
            outputs = {
                    @Output(OutputNames.RETURN_RESULT),
                    @Output("result_message")
            },
            responses = {
                    @Response(text = ResponseNames.SUCCESS, field = OutputNames.RETURN_RESULT, value = "0", matchType = MatchType.COMPARE_GREATER_OR_EQUAL, responseType = ResponseType.RESOLVED),
                    @Response(text = ResponseNames.FAILURE, field = OutputNames.RETURN_RESULT, value = "0", matchType = MatchType.COMPARE_LESS, responseType = ResponseType.ERROR)
            })
    public Map<String, String> checkPositiveSum(@Param("op1") int x, @Param("op2") int y) {
        Map<String, String> resultMap = new HashMap<String, String>();

        //Calculate sum
        int sum = x + y;

        //The "result" output
        resultMap.put(OutputNames.RETURN_RESULT, String.valueOf(sum));

        //The "result_message" output
        if (sum >= 0) {
            resultMap.put("result_message", "This is a good sum");
        } else {
            resultMap.put("result_message", "This is a bad sum");
        }

        return resultMap;
    }
}
