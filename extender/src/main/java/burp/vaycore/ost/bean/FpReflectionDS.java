package burp.vaycore.ost.bean;

import burp.vaycore.ost.common.ReflectionProbe;

/** Request/response correlation exposed through the existing fingerprint field selector. */
public final class FpReflectionDS {
    private final String marker;
    private final boolean reflected;

    public FpReflectionDS(FpHttpReqDS request, FpHttpRespDS response) {
        marker = request == null ? "" : ReflectionProbe.markerFromRequest(request.getData());
        reflected = !marker.isEmpty() && response != null && response.getBody().contains(marker);
    }
}
