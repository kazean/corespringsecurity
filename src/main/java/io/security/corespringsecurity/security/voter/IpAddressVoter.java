package io.security.corespringsecurity.security.voter;

import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.Collection;
import java.util.List;

@RequiredArgsConstructor
public class IpAddressVoter implements AccessDecisionVoter {

    private final SecurityResourceService securityResourceService;

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public int vote(Authentication authentication, Object object, Collection collection) {
        WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
        String remoteAddress = details.getRemoteAddress();

        int result = ACCESS_DENIED;
        List<String> accessIpList = securityResourceService.getAccessIpList();
        for (String accessIp : accessIpList) {
            if (accessIp.equals(remoteAddress)) {
                result = ACCESS_ABSTAIN;
                break;
            }
        }

        if (result == ACCESS_DENIED) {
            throw new AccessDeniedException("Invaild Your Ip address");
        }
        return result;
    }

    @Override
    public boolean supports(Class clazz) {
        return true;
    }
}
