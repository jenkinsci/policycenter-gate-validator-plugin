/*
 * Copyright 2016 Parasoft Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.parasoft.policycenter.jenkins;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletException;
import javax.xml.bind.DatatypeConverter;

import hudson.Launcher;
import hudson.Extension;
import hudson.util.FormValidation;
import hudson.util.Secret;
import hudson.util.ListBoxModel;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.Result;
import hudson.model.AbstractProject;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

public class CheckGateBuilder extends Builder {

    private final String project;
    private final String gate;
    private static final Logger _LOGGER = Logger.getLogger(CheckGateBuilder.class.getName());

    @DataBoundConstructor
    public CheckGateBuilder(String project, String gate) {
        this.project = project;
        this.gate = gate;
    }

    public final String getProject() {
        return project;
    }
    
    public final String getGate() {
        return gate;
    }

    private JSONObject getGateStatus(String url, BuildListener listener) {
        String result = getDescriptor().getData(url, listener);
        JSONArray resultArr = JSONArray.fromObject(result);
        if (resultArr.size() == 0) {
            if ("-2".equals(gate)) {
                listener.getLogger().println("No previous gate exists for this project.");
            } else if ("-1".equals(gate)) {
                listener.getLogger().println("No next gate exists for this project.");
            } else {
                listener.getLogger().println("No status of the gate exists.");
            }
            return null;
        }
        return resultArr.getJSONObject(0);
    }
    
    @Override
    public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) throws InterruptedException {
        DescriptorImpl descriptor = getDescriptor();
        descriptor.loadData();  // update projectsArr and gatesArr
        String url = descriptor.getPcUrl() + "/api/v1/gates/";
        if ("-3".equals(gate)) {
            listener.getLogger().println("There are no gates for this project.");
            build.setResult(Result.UNSTABLE);
            return true;
        } else if ("-2".equals(gate)) {
//          if (mostRecentGate == null) {
//              listener.getLogger().println("No most recent gate exists for this project.");
//              build.setResult(Result.UNSTABLE);
//              return true;
//          }
            url += "previous/status?projectId=" + getProject();
            listener.getLogger().println("Checking status of previous gate...");
        } else if ("-1".equals(gate)) {
            url += "next/status?projectId=" + getProject();
            listener.getLogger().println("Checking status of next gate...");
        } else {
            url += getGate() + "/status?projectId=" + getProject();
            listener.getLogger().println("Checking status of gate '" + descriptor.getGateNameById(getGate()) + "'...");
        }
        JSONObject statusObj = getGateStatus(url, listener);
        if (statusObj == null) {
            build.setResult(Result.FAILURE);
            return true;
        }
        String status = statusObj.getString("value").toUpperCase();
        if ("WAITING".equals(status)) {
            listener.getLogger().println("Waiting for Policy Center to calculate the status...");
        }
        while ("WAITING".equals(status)) {
            Thread.sleep(1000);
            statusObj = getGateStatus(url, listener);
            if (statusObj == null) {
                build.setResult(Result.FAILURE);
                return true;
            }
            status = statusObj.getString("value").toUpperCase();
        }
        listener.getLogger().println("Status of gate '" + descriptor.getGateNameById(statusObj.getString("gateId")) + "' is: " + status);
        JSONArray substatus = statusObj.getJSONArray("substatus");
        for (int i = 0; i < substatus.size(); i++) {
            JSONObject gateStatusGroup = substatus.getJSONObject(i);
            listener.getLogger().println();
            listener.getLogger().println("Policies with status " + gateStatusGroup.getString("status") + ":");
            JSONArray policies = gateStatusGroup.getJSONArray("policies");
            for (int j = 0; j < policies.size(); j++) {
                JSONObject policy = policies.getJSONObject(j);
                listener.getLogger().println("  " + policy.getString("name"));
                JSONArray messages = policy.getJSONArray("messages");
                for (int k = 0; k < messages.size(); k++) {
                    listener.getLogger().println("    * " + messages.getString(k));
                }
            }
        }
        listener.getLogger().println();
        if ("SUCCESS".equals(status)) {
            build.setResult(Result.SUCCESS);
        } else if ("ERROR".equals(status)) {
            build.setResult(Result.FAILURE);
        } else if ("UNSTABLE".equals(status)) {
            build.setResult(Result.UNSTABLE);
        } else if ("NODATA".equals(status)) {
            build.setResult(Result.FAILURE);
        } else {
            listener.getLogger().println("Status of the gate should be one of these: SUCCESS, ERROR, UNSTABLE or NODATA.");
            build.setResult(Result.FAILURE);
        }
        
        return true;
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl)super.getDescriptor();
    }

    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {

        private String pcUrl;
        private String pcUsername;
        private Secret pcPassword;
        
        private JSONArray projectsArr;
        
        private JSONArray gatesArr;
        
        private static final Logger _LOGGER = Logger.getLogger(DescriptorImpl.class.getName());
        
        public FormValidation doCheckPcUrl(@QueryParameter String value)
                throws IOException, ServletException {
            if (value.length() == 0)
                return FormValidation.error("Please set Policy Center URL");
            if (!value.startsWith("http://") && !value.startsWith("https://"))
                return FormValidation.error("Please enter a valid URL. Protocol is required (http:// or https://)");
            return FormValidation.ok();
        }
        
        public FormValidation doCheckPcUsername(@QueryParameter String value)
                throws IOException, ServletException {
            if (value.trim().equals("") && ((pcUsername == null) || pcUsername.trim().equals(""))) {
                return FormValidation.error("Please set Policy Center username");
            } else {
                return FormValidation.ok();
            }
        }

        public FormValidation doCheckPcPassword(@QueryParameter String value)
                throws IOException, ServletException {
            if (value.trim().equals("") && ((pcPassword == null) || pcPassword.getPlainText().trim().equals(""))) {
                return FormValidation.warning("lease set Policy Center password");
            } else {
                return FormValidation.ok();
            }
        }
        
        private String removeTrailingChar(String str, char c) {
            int lastIndex = str.length() - 1;
            while (lastIndex >= 0 && str.charAt(lastIndex) == c) {
                lastIndex--;
            }
            return str.substring(0, lastIndex + 1);
        }
        
        public FormValidation doTestConnection(@QueryParameter String pcUrl, 
                @QueryParameter String pcUsername, @QueryParameter String pcPassword)
                throws IOException, ServletException {
            URL obj;
            try {
                String url = removeTrailingChar(pcUrl, ' ');
                url = removeTrailingChar(url, '/');
                url += "/api/v1/projects";
                obj = new URL(url);
                HttpURLConnection con = (HttpURLConnection) obj.openConnection();
                String userCredentials = pcUsername.trim() + ":" + pcPassword.trim();
                String basicAuth = "Basic " + DatatypeConverter.printBase64Binary(userCredentials.getBytes("UTF-8"));
                con.setRequestProperty ("Authorization", basicAuth);
                if ("https".equals(obj.getProtocol())) { //$NON-NLS-1$
                    ((HttpsURLConnection)con).setSSLSocketFactory(getTrustAllSslSocketFactory());
                    ((HttpsURLConnection)con).setHostnameVerifier(DO_NOT_VERIFY);
                }
                int responseCode = con.getResponseCode();
                if (responseCode == 200) {
                    return FormValidation.ok("Success.");
                } else if (responseCode == 401) {
                    return FormValidation.error("Invalid username or password.");
                } else {
                    return FormValidation.error("Policy Center URL is not configured correctly.");
                }
            } catch (Exception e) {
                _LOGGER.log(Level.SEVERE, pcUrl, e);
                return FormValidation.error("Policy Center URL is not configured correctly.");
            }
        }
        
        // always verify the host - dont check for certificate
        final static HostnameVerifier DO_NOT_VERIFY = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
        
        private static SSLSocketFactory TRUST_ALL_SSL = null;

        private static SSLSocketFactory getTrustAllSslSocketFactory() throws GeneralSecurityException, IOException
        {
            synchronized (DO_NOT_VERIFY) {
                if (TRUST_ALL_SSL != null) {
                    return TRUST_ALL_SSL;
                }
                // Create a trust manager that does not validate certificate chains
                TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[] {};
                    }
                    public void checkClientTrusted(X509Certificate[] chain,
                        String authType) throws CertificateException {
                    }
                    public void checkServerTrusted(X509Certificate[] chain,
                        String authType) throws CertificateException {
                    }
                } };
                SSLContext context = SSLContext.getInstance("TLS"); //$NON-NLS-1$
                context.init(null, trustAllCerts, new SecureRandom());
                TRUST_ALL_SSL = context.getSocketFactory();
                return TRUST_ALL_SSL;
            }
        }
        
        public String getGateNameById(String gateId) {
            for (int i = 0; i < gatesArr.size(); i++) {
                JSONObject gate = gatesArr.getJSONObject(i);
                if (gateId.endsWith(gate.getString("id"))) {
                    return gate.getString("name");
                }
            }
            return null;
        }
        
        public String getData(String url, BuildListener listener) {
            URL obj;
            BufferedReader in = null;
            HttpURLConnection con = null;
            try {
                obj = new URL(url);
                con = (HttpURLConnection) obj.openConnection();
                String userCredentials = pcUsername.trim() + ":" + pcPassword.getPlainText().trim();
                String basicAuth = "Basic " + DatatypeConverter.printBase64Binary(userCredentials.getBytes("UTF-8"));
                con.setRequestProperty ("Authorization", basicAuth);
                if ("https".equals(obj.getProtocol())) { //$NON-NLS-1$
                    ((HttpsURLConnection)con).setSSLSocketFactory(getTrustAllSslSocketFactory());
                    ((HttpsURLConnection)con).setHostnameVerifier(DO_NOT_VERIFY);
                }
                in = new BufferedReader(new InputStreamReader(con.getInputStream(), Charset.defaultCharset()));
                String inputLine;
                StringBuffer response = new StringBuffer();
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                return response.toString();
            } catch (Exception e) {
                _LOGGER.log(Level.SEVERE, url, e);
                try {
                    if (con.getResponseCode() == 401) {
                        if (null != listener) {
                            listener.getLogger().println("Policy Center username or password may not be properly configured.");
                        }
                    }
                } catch (IOException e1) {
                    _LOGGER.log(Level.SEVERE, e1.getMessage(), e1);
                }
                return null;
            } finally {
                if (in != null) {
                    try {
                        in.close();
                    } catch (IOException e) {
                        _LOGGER.log(Level.WARNING, e.getMessage(), e);
                    }
                }
            }
        }
        
        public void loadData() {
            String projects = getData(pcUrl + "/api/v1/projects", null);
            if (projects != null) {
                projectsArr = JSONArray.fromObject(projects);
            }
            String gates = getData(pcUrl + "/api/v1/gates", null);
            if (gates != null) {
                gatesArr = JSONArray.fromObject(gates);
            }
        }
        
        private JSONArray getGatesForProject(String projectId) {
            JSONArray itemsArr = new JSONArray();
            if (gatesArr != null && projectsArr != null) {
                JSONArray gates = null;
                for (int i = 0; i < projectsArr.size(); i++) {
                    JSONObject projectObj = projectsArr.getJSONObject(i);
                    if (projectObj.getString("id").equals(projectId) && projectObj.containsKey("gates")) {
                        gates = projectObj.getJSONArray("gates");
                    }
                }
                if (gates != null) {
                    for (int j = 0; j < gates.size(); j++) {
                        for (int k = 0; k < gatesArr.size(); k++) {
                            JSONObject gateObj = gatesArr.getJSONObject(k);
                            if (gates.getString(j).equals(gateObj.getString("id"))) {
                                itemsArr.add(gateObj);
                            }
                        }
                    }
                }
            }
            return itemsArr;
        }
        
        public ListBoxModel doFillProjectItems() throws IOException, GeneralSecurityException {
            ListBoxModel items = new ListBoxModel();
            if (null == pcUrl || ("").equals(pcUrl)) {
                items.add("No Policy Center URL configured.");
            } else if (!pcUrl.startsWith("http://") && !pcUrl.startsWith("https://")) {
                items.add("Policy Center URL is not valid. Protocol is required (http:// or https://)");
            } else {
                loadData();
                if (projectsArr != null) {
                    for (int i = 0; i < projectsArr.size(); i++) {
                        JSONObject projectObj = projectsArr.getJSONObject(i);
                        items.add(projectObj.getString("name"), projectObj.getString("id"));
                    }
                }
            }
            
            return items;
        }
        
        public ListBoxModel doFillGateItems(@QueryParameter String project) {
            ListBoxModel items = new ListBoxModel();
            JSONArray itemsArr = getGatesForProject(project);
            if (itemsArr.size() == 0) {
                items.add("There are no gates for this project.", "-3");
            } else {
                items.add("-- Next Gate --", "-1");
                items.add("-- Previous Gate --", "-2");
                for (int i = 0; i < itemsArr.size(); i++) {
                    JSONObject gateObj = itemsArr.getJSONObject(i);
                    items.add(gateObj.getString("name"), gateObj.getString("id"));
                }
            }
            return items;
        }

        public DescriptorImpl() {
            load();
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "Check Policy Gate";
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            pcUrl = formData.getString("pcUrl");  // Can also use req.bindJSON(this, formData); (easier when there are many fields)
            pcUrl = removeTrailingChar(pcUrl, ' ');
            pcUrl = removeTrailingChar(pcUrl, '/');
            pcUsername = formData.getString("pcUsername");
            pcPassword = Secret.fromString(formData.getString("pcPassword"));
            save();
            return super.configure(req, formData);
        }

        public String getPcUrl() {
            return pcUrl;
        }
        
        public String getPcUsername() {
            return pcUsername;
        }

        public String getPcPassword() {
            return pcPassword.getPlainText();
        }
    }
}
