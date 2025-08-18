package com.stark.jarvis.cipher.core;

import lombok.Data;
import lombok.experimental.Accessors;
import org.apache.commons.lang3.StringUtils;

import java.io.Serializable;

import static java.util.Objects.requireNonNull;

/**
 * 证书主题信息
 *
 * @author <a href="mengbin@hotmail.com">Ben</a>
 * @version 1.0.0
 * @since 1.0.0, 2025/8/14
 */
@Data
@Accessors(chain = true)
public class SubjectInfo implements Serializable {

    private static final long serialVersionUID = -1268855048354296969L;

    /**
     * 通用名称（CN），必填
     * <ul>
     *     <li>对于SSL证书：通常是域名（如 *.example.com）</li>
     *     <li>对于个人证书：可能是人名或用户ID</li>
     *     <li>对于CA证书：包含"CA"标识（如 My Root CA）</li>
     * </ul>
     */
    private String commonName;

    /**
     * 组织单位（OU）
     */
    private String organizationalUnit;

    /**
     * 组织名称（O）
     */
    private String organization;

    /**
     * 城市或区域名称（L）
     */
    private String locality;

    /**
     * 省/市/自治区名称（ST）
     */
    private String stateOrProvince;

    /**
     * 国家/地区代码（C）
     */
    private String country;

    /**
     * 街道地址（STREET）
     */
    private String streetAddress;

    /**
     * 域名组件（DC）
     */
    private String domainComponent;

    /**
     * 用户标识符（UID）
     */
    private String userId;

    public String toX500Name() {
        requireNonNull(commonName);

        StringBuilder sb = new StringBuilder()
                .append("CN=").append(commonName);
        if (StringUtils.isNotBlank(organizationalUnit)) {
            sb.append(", OU=").append(organizationalUnit);
        }
        if (StringUtils.isNotBlank(organization)) {
            sb.append(", O=").append(organization);
        }
        if (StringUtils.isNotBlank(locality)) {
            sb.append(", L=").append(locality);
        }
        if (StringUtils.isNotBlank(stateOrProvince)) {
            sb.append(", ST=").append(stateOrProvince);
        }
        if (StringUtils.isNotBlank(country)) {
            sb.append(", C=").append(country);
        }
        if (StringUtils.isNotBlank(streetAddress)) {
            sb.append(", STREET=").append(streetAddress);
        }
        if (StringUtils.isNotBlank(domainComponent)) {
            sb.append(", DC=").append(domainComponent);
        }
        if (StringUtils.isNotBlank(userId)) {
            sb.append(", UID=").append(userId);
        }
        return sb.toString();
    }

}
