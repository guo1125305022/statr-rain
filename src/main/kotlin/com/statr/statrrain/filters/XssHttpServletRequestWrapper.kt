package com.statr.statrrain.filters

import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import java.io.ByteArrayInputStream
import java.io.IOException
import java.util.LinkedHashMap
import javax.servlet.ReadListener
import javax.servlet.ServletInputStream
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletRequestWrapper

class XssHttpServletRequestWrapper(request: HttpServletRequest?) : HttpServletRequestWrapper(request) {
    //没被包装过的HttpServletRequest（特殊场景，需要自己过滤）
    internal var orgRequest: HttpServletRequest
    //html过滤
    private val htmlFilter = HTMLFilter()

    constructor(request: HttpServletRequest):super(request) {
        orgRequest = request
    }

    @Throws(IOException::class)
    override fun getInputStream(): ServletInputStream {
        //非json类型，直接返回
        if (!MediaType.APPLICATION_JSON_VALUE.equals(super.getHeader(HttpHeaders.CONTENT_TYPE), ignoreCase = true)) {
            return super.getInputStream()
        }

        //为空，直接返回
        var json = IOUtils.toString(super.getInputStream(), "utf-8")
        if (StringUtils.isBlank(json)) {
            return super.getInputStream()
        }

        //xss过滤
        json = xssEncode(json)
        val bis = ByteArrayInputStream(json.toByteArray(charset("utf-8")))
        return object : ServletInputStream() {
            override fun isFinished(): Boolean {
                return true
            }

            override fun isReady(): Boolean {
                return true
            }

            override fun setReadListener(readListener: ReadListener) {

            }

            @Throws(IOException::class)
            override fun read(): Int {
                return bis.read()
            }
        }
    }

    override fun getParameter(name: String): String {
        var value = super.getParameter(xssEncode(name))
        if (StringUtils.isNotBlank(value)) {
            value = xssEncode(value)
        }
        return value
    }

    override fun getParameterValues(name: String): Array<String>? {
        val parameters = super.getParameterValues(name)
        if (parameters == null || parameters.size == 0) {
            return null
        }

        for (i in parameters.indices) {
            parameters[i] = xssEncode(parameters[i])
        }
        return parameters
    }

    override fun getParameterMap(): Map<String, Array<String>> {
        val map = LinkedHashMap<String, Array<String>>()
        val parameters = super.getParameterMap()
        for (key in parameters.keys) {
            val values = parameters[key]
            for (i in values.indices) {
                values[i] = xssEncode(values[i])
            }
            map[key] = values
        }
        return map
    }

    override fun getHeader(name: String): String {
        var value = super.getHeader(xssEncode(name))
        if (StringUtils.isNotBlank(value)) {
            value = xssEncode(value)
        }
        return value
    }

    private fun xssEncode(input: String): String {
        return htmlFilter.filter(input)
    }

    /**
     * 获取最原始的request
     */
    fun getOrgRequest(): HttpServletRequest {
        return orgRequest
    }

    /**
     * 获取最原始的request
     */
    fun getOrgRequest(request: HttpServletRequest): HttpServletRequest {
        return (request as? XssHttpServletRequestWrapper)?.getOrgRequest() ?: request

    }
}