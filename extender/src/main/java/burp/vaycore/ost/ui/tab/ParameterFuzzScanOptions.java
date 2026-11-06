package burp.vaycore.ost.ui.tab;

import burp.vaycore.ost.bean.TaskData;
import burp.vaycore.ost.common.ParameterFuzzRequestBuilder;
import burp.vaycore.ost.common.RequestMode;

import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Collections;
import java.util.Objects;

/** One submission may contain different modes, dictionaries and transports for each endpoint. */
public record ParameterFuzzScanOptions(List<TargetOptions> scans) {
    public ParameterFuzzScanOptions {
        scans = List.copyOf(scans == null ? List.of() : scans);
    }

    public enum Mode { NAMES, VALUES, POSITIONS }

    /** Immutable configuration snapshot; no worker reads the current UI controls. */
    public record TargetOptions(
            TaskData target,
            Mode mode,
            List<String> parameterNameCandidates,
            List<String> parameterValues,
            byte[] requestTemplate,
            Map<String, List<String>> positionValues,
            boolean scanGet,
            boolean scanPost,
            boolean onlyExistingRoutes,
            RequestMode requestMode,
            String browserId) {
        public TargetOptions {
            Objects.requireNonNull(target, "target");
            Objects.requireNonNull(mode, "mode");
            parameterNameCandidates = List.copyOf(parameterNameCandidates == null ? List.of() : parameterNameCandidates);
            parameterValues = List.copyOf(parameterValues == null ? List.of() : parameterValues);
            requestTemplate = requestTemplate == null ? new byte[0] : requestTemplate.clone();
            Map<String, List<String>> snapshot = new LinkedHashMap<>();
            if (positionValues != null) positionValues.forEach((id, values) -> snapshot.put(id, List.copyOf(values)));
            positionValues = Collections.unmodifiableMap(snapshot);
            requestMode = requestMode == RequestMode.BROWSER ? RequestMode.BROWSER : RequestMode.BURP;
            browserId = requestMode == RequestMode.BURP || browserId == null ? "" : browserId.trim();
        }

        public boolean customPositions() { return mode == Mode.POSITIONS; }
        public boolean discoverParameterNames() { return mode == Mode.NAMES; }

        public boolean eligible() {
            return ParameterFuzzRequestBuilder.isSelectedMethod(target.getMethod(), scanGet, scanPost)
                    && (!onlyExistingRoutes || ParameterFuzzRequestBuilder.isExistingRoute(target.getStatus()))
                    && (!customPositions() || ParameterFuzzRequestBuilder.isSelectedMethod(
                    ParameterFuzzRequestBuilder.requestMethod(requestTemplate), scanGet, scanPost));
        }

        @Override public byte[] requestTemplate() { return requestTemplate.clone(); }
    }
}
