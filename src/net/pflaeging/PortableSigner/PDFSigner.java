/*
 * PDFSigner.java
 *
 * Created on 05. May 2009, 15:25
 * This File is part of PortableSigner (http://portablesigner.sf.net/)
 *  and is under the European Public License V1.1 (http://www.osor.eu/eupl)
 * (c) Peter Pfläging <peter@pflaeging.net>
 * Patches and bugfixes from: dzoe@users.sourceforge.net
 * 
 * 20. March 2023: SHA2 patch by Sven Plaga (git@dl1ps.de):
 *  - use of SHA1 is INSECURE: https://shattered.io/ 
 *    - so the integrity of all documents signed with the original implementation of PortableSigner is no longer guaranteed
 *  - this patch replaces SHA1 with SHA2 (256) enabling PortableSigner making secure signatures, again!
 * 
 */
package net.pflaeging.PortableSigner;

import com.lowagie.text.Chunk;
import com.lowagie.text.Font;
import com.lowagie.text.Image;
import com.lowagie.text.pdf.PdfContentByte;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.util.Date;
import java.util.ResourceBundle;

import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.Rectangle;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.xml.xmp.XmpWriter;
import java.io.ByteArrayOutputStream;
import java.util.HashMap;

/* Classes added for SHA2 patch */
import java.security.Signature;
import java.security.SignatureException;
import java.util.Calendar;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfDate;
import java.security.cert.X509Certificate;
import com.lowagie.text.pdf.PdfString;
import com.lowagie.text.pdf.PdfSignature;
import com.lowagie.text.pdf.PdfPKCS7;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.MessageDigest;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

/**
 * 
 * @author peter@pflaeging.net
 */
public class PDFSigner {

    private static GetPKCS12 pkcs12;
    public float ptToCm = (float) 0.0352777778;

    /** Creates a new instance of DoSignPDF */
    public void doSignPDF(String pdfInputFileName,
            String pdfOutputFileName,
            String pkcs12FileName,
            String password,
            Boolean signText,
            String signLanguage,
            String sigLogo,
            Boolean finalize,
            String sigComment,
            String signReason,
            String signLocation,
            Boolean noExtraPage,
            float verticalPos,
            float leftMargin,
            float rightMargin,
            Boolean signLastPage,
            byte[] ownerPassword) throws PDFSignerException{
        try {
            //System.out.println("-> DoSignPDF <-");
            //System.out.println("Eingabedatei: " + pdfInputFileName);
            //System.out.println("Ausgabedatei: " + pdfOutputFileName);
            //System.out.println("Signaturdatei: " + pkcs12FileName);
            //System.out.println("Signaturblock?: " + signText);
            //System.out.println("Sprache der Blocks: " + signLanguage);
            //System.out.println("Signaturlogo: " + sigLogo);
            System.err.println("Position V:" + verticalPos + " L:" + leftMargin + " R:" + rightMargin);
            Rectangle signatureBlock;

            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            //java.security.Security.insertProviderAt(
            //        new org.bouncycastle.jce.provider.BouncyCastleProvider(), 2);
            pkcs12 = new GetPKCS12(pkcs12FileName, password);

            PdfReader reader = null;
            try {
//                System.out.println("Password:" + ownerPassword.toString());
				if (ownerPassword == null)
					reader = new PdfReader(pdfInputFileName);
				else
					reader = new PdfReader(pdfInputFileName, ownerPassword);
            } catch (IOException e) {
            	
            	/* MODIFY BY: Denis Torresan
                Main.setResult(
                        java.util.ResourceBundle.getBundle(
                        "net/pflaeging/PortableSigner/i18n").getString(
                        "CouldNotBeOpened"),
                        true,
                        e.getLocalizedMessage());
                */
            	throw new PDFSignerException(
            			java.util.ResourceBundle.getBundle(
                        "net/pflaeging/PortableSigner/i18n").getString(
                        "CouldNotBeOpened"),
                        true,
                        e.getLocalizedMessage() );
            }
            FileOutputStream fout = null;
            try {
                fout = new FileOutputStream(pdfOutputFileName);
            } catch (FileNotFoundException e) {
            	
            	/* MODIFY BY: Denis Torresan
                Main.setResult(
                        java.util.ResourceBundle.getBundle("net/pflaeging/PortableSigner/i18n").getString("CouldNotBeWritten"),
                        true,
                        e.getLocalizedMessage());
                */
            	
            	throw new PDFSignerException(
            			java.util.ResourceBundle.getBundle("net/pflaeging/PortableSigner/i18n").getString("CouldNotBeWritten"),
                        true,
                        e.getLocalizedMessage() );
       	
            }
            PdfStamper stp = null;
            try {
                
                /* Get the date */          
                Date datum = new Date(System.currentTimeMillis());

                int pages = reader.getNumberOfPages();

                Rectangle size = reader.getPageSize(pages);
                stp = PdfStamper.createSignature(reader, fout, '\0', null, true);
                
                /*  
                 * remove metadata section 
                 * Attention: itext in version  2.1.7 does not allow changing producer (if open source license is used)
                 *            so existing code which modifies producer to  "signed with PortableSigner" is defunct
                 */
                boolean RemovePdfMetaData = false;  // TODO: integrate switch to GUI (new feature)
                
                HashMap<String, String> pdfInfo = reader.getInfo(); 
                
                if (RemovePdfMetaData) {        // if selected: remove PDF meta-data for privacy reasons
                    reader.getCatalog().remove(PdfName.METADATA);
                    reader.removeUnusedObjects();    

                    pdfInfo.put("Title", null);
                    pdfInfo.put("Author", null);
                    pdfInfo.put("Subject", null);
                    pdfInfo.put("Keywords", null);
                    pdfInfo.put("Creator", null);
                    // pdfInfo.put("Producer", null);  // not allowed in open-source version of itext library
                    /* old code - defunct in open-source version of itext library!
                    String pdfInfoProducer = "";
                    if( pdfInfo.get("Producer") != null ) {
                	pdfInfoProducer = pdfInfo.get("Producer").toString();
                        pdfInfoProducer = pdfInfoProducer + " (signed with PortableSigner " + Version.release + ")";
                    } else {
                        pdfInfoProducer = "Unknown Producer (signed with PortableSigner " + Version.release + ")";
                    }
                    pdfInfo.put("Producer", pdfInfoProducer);
                    */
                    pdfInfo.put("CreationDate", null);
                    pdfInfo.put("ModDate", null);
                    pdfInfo.put("Trapped", null);
                    pdfInfo.put("Producer", null);
                }
                
                //System.err.print("++ Producer:" + pdfInfo.get("Producer").toString());
                stp.setMoreInfo(pdfInfo);
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
		XmpWriter xmp = new XmpWriter(baos, pdfInfo);
		xmp.close();
		stp.setXmpMetadata(baos.toByteArray());
                if (signText) {
                    String greet, signator, datestr, ca, serial, special, note, urn, urnvalue;
                    int specialcount = 0;
                    int sigpage;
                    int rightMarginPT, leftMarginPT;
                    float verticalPositionPT;
                    ResourceBundle block = ResourceBundle.getBundle(
                            "net/pflaeging/PortableSigner/Signatureblock_" + signLanguage);
                    greet = block.getString("greeting");
                    signator = block.getString("signator");
                    datestr = block.getString("date");
                    ca = block.getString("issuer");
                    serial = block.getString("serial");
                    special = block.getString("special");
                    note = block.getString("note");
                    urn = block.getString("urn");
                    urnvalue = block.getString("urnvalue");


                    //sigcomment = block.getString(signLanguage + "-comment");
                   // upper y
                    float topy = size.getTop();
                    System.err.println("Top: " + topy * ptToCm);
                    // right x
                    float rightx = size.getRight();
                    System.err.println("Right: " + rightx * ptToCm);
                    if (!noExtraPage) {
                        sigpage = pages + 1;
                        stp.insertPage(sigpage, size);
                        // 30pt left, 30pt right, 20pt from top
                        rightMarginPT = 30;
                        leftMarginPT = 30;
                        verticalPositionPT = topy - 20;
                    } else {
                        if (signLastPage) {
                            sigpage = pages;
                        } else {
                            sigpage = 1;
                        }
                        System.err.println("Page: " + sigpage);
                        rightMarginPT = Math.round(rightMargin / ptToCm);
                        leftMarginPT = Math.round(leftMargin / ptToCm);
                        verticalPositionPT = topy - Math.round(verticalPos / ptToCm);
                    }
                    if (!GetPKCS12.atEgovOID.equals("")) {
                        specialcount = 1;
                    }
                    PdfContentByte content = stp.getOverContent(sigpage);
                    
                    float[] cellsize = new float[2];
                    cellsize[0] = 100f;
                    // rightx = width of page
                    // 60 = 2x30 margins
                    // cellsize[0] = description row
                    // cellsize[1] = 0
                    // 70 = logo width
                    cellsize[1] = rightx - rightMarginPT - leftMarginPT - cellsize[0] - cellsize[1] - 70;

                    // Pagetable = Greeting, signatureblock, comment
                    // sigpagetable = outer table
                    //      consist: greetingcell, signatureblock , commentcell
                    PdfPTable signatureBlockCompleteTable = new PdfPTable(2);
                    PdfPTable signatureTextTable = new PdfPTable(2);
                    PdfPCell signatureBlockHeadingCell =
                            new PdfPCell(new Paragraph(
                            new Chunk(greet,
                            new Font(Font.HELVETICA, 12))));
                    signatureBlockHeadingCell.setPaddingBottom(5);
                    signatureBlockHeadingCell.setColspan(2);
                    signatureBlockHeadingCell.setBorderWidth(0f);
                    signatureBlockCompleteTable.addCell(signatureBlockHeadingCell);

                    // inner table start
                    // Line 1
                    signatureTextTable.addCell(
                            new Paragraph(
                            new Chunk(signator, new Font(Font.HELVETICA, 10, Font.BOLD))));
                    signatureTextTable.addCell(
                            new Paragraph(
                            new Chunk(GetPKCS12.subject, new Font(Font.COURIER, 10))));
                    // Line 2
                    signatureTextTable.addCell(
                            new Paragraph(
                            new Chunk(datestr, new Font(Font.HELVETICA, 10, Font.BOLD))));
                    signatureTextTable.addCell(
                            new Paragraph(
                            new Chunk(datum.toString(), new Font(Font.COURIER, 10))));
                    // Line 3
                    signatureTextTable.addCell(
                            new Paragraph(
                            new Chunk(ca, new Font(Font.HELVETICA, 10, Font.BOLD))));
                    signatureTextTable.addCell(
                            new Paragraph(
                            new Chunk(GetPKCS12.issuer, new Font(Font.COURIER, 10))));
                    // Line 4
                    signatureTextTable.addCell(
                            new Paragraph(
                            new Chunk(serial, new Font(Font.HELVETICA, 10, Font.BOLD))));
                    signatureTextTable.addCell(
                            new Paragraph(
                            new Chunk(GetPKCS12.serial.toString(), new Font(Font.COURIER, 10))));
                    // Line 5
                    if (specialcount == 1) {
                        signatureTextTable.addCell(
                                new Paragraph(
                                new Chunk(special, new Font(Font.HELVETICA, 10, Font.BOLD))));
                        signatureTextTable.addCell(
                                new Paragraph(
                                new Chunk(GetPKCS12.atEgovOID, new Font(Font.COURIER, 10))));
                    }
                    signatureTextTable.addCell(
                            new Paragraph(
                            new Chunk(urn, new Font(Font.HELVETICA, 10, Font.BOLD))));
                    signatureTextTable.addCell(
                            new Paragraph(
                            new Chunk(urnvalue, new Font(Font.COURIER, 10))));
                    signatureTextTable.setTotalWidth(cellsize);
                    System.err.println("signatureTextTable Width: " + cellsize[0] * ptToCm + " " + cellsize[1] * ptToCm);
                    // inner table end

                    signatureBlockCompleteTable.setHorizontalAlignment(PdfPTable.ALIGN_CENTER);
                    Image logo;
//                     System.out.println("Logo:" + sigLogo + ":");
                    if (sigLogo == null || "".equals(sigLogo)) {
                        logo = Image.getInstance(getClass().getResource(
                                "/net/pflaeging/PortableSigner/SignatureLogo.png"));
                    } else {
                        logo = Image.getInstance(sigLogo);
                    }
                    
                    PdfPCell logocell = new PdfPCell();
                    logocell.setVerticalAlignment(PdfPCell.ALIGN_MIDDLE);
                    logocell.setHorizontalAlignment(PdfPCell.ALIGN_CENTER);
                    logocell.setImage(logo);
                    signatureBlockCompleteTable.addCell(logocell);
                    PdfPCell incell = new PdfPCell(signatureTextTable);
                    incell.setBorderWidth(0f);
                    signatureBlockCompleteTable.addCell(incell);
                    PdfPCell commentcell =
                            new PdfPCell(new Paragraph(
                            new Chunk(sigComment,
                            new Font(Font.HELVETICA, 10))));
                    PdfPCell notecell =
                            new PdfPCell(new Paragraph(
                            new Chunk(note,
                            new Font(Font.HELVETICA, 10, Font.BOLD))));
                    //commentcell.setPaddingTop(10);
                    //commentcell.setColspan(2);
                    // commentcell.setBorderWidth(0f);
                    if (!sigComment.equals("")) {
                        signatureBlockCompleteTable.addCell(notecell);
                        signatureBlockCompleteTable.addCell(commentcell);
                    }
                    float[] cells = {70, cellsize[0] + cellsize[1]};
                    signatureBlockCompleteTable.setTotalWidth(cells);
                    System.err.println("signatureBlockCompleteTable Width: " + cells[0] * ptToCm + " " + cells[1] * ptToCm);
                    signatureBlockCompleteTable.writeSelectedRows(0, 4 + specialcount, leftMarginPT, verticalPositionPT, content);
                    System.err.println("signatureBlockCompleteTable Position " + 30 * ptToCm + " " + (topy - 20) * ptToCm);
                    signatureBlock = new Rectangle( 30 + signatureBlockCompleteTable.getTotalWidth() - 20,
                            topy - 20 - 20,
                            30 + signatureBlockCompleteTable.getTotalWidth(),
                            topy - 20);
//                    //////
//                    AcroFields af = reader.getAcroFields();
//                    ArrayList names = af.getSignatureNames();
//                    for (int k = 0; k < names.size(); ++k) {
//                        String name = (String) names.get(k);
//                        System.out.println("Signature name: " + name);
//                        System.out.println("\tSignature covers whole document: " + af.signatureCoversWholeDocument(name));
//                        System.out.println("\tDocument revision: " + af.getRevision(name) + " of " + af.getTotalRevisions());
//                        PdfPKCS7 pk = af.verifySignature(name);
//                        X509Certificate tempsigner = pk.getSigningCertificate();
//                        Calendar cal = pk.getSignDate();
//                        Certificate pkc[] = pk.getCertificates();
//                        java.util.ResourceBundle tempoid =
//                                java.util.ResourceBundle.getBundle("net/pflaeging/PortableSigner/SpecialOID");
//                        String tmpEgovOID = "";
//
//                        for (Enumeration<String> o = tempoid.getKeys(); o.hasMoreElements();) {
//                            String element = o.nextElement();
//                            // System.out.println(element + ":" + oid.getString(element));
//                            if (tempsigner.getNonCriticalExtensionOIDs().contains(element)) {
//                                if (!tmpEgovOID.equals("")) {
//                                    tmpEgovOID += ", ";
//                                }
//                                tmpEgovOID += tempoid.getString(element) + " (OID=" + element + ")";
//                            }
//                        }
//                        //System.out.println("\tSigniert von: " + PdfPKCS7.getSubjectFields(pk.getSigningCertificate()));
//                        System.out.println("\tSigniert von: " + tempsigner.getSubjectX500Principal().toString());
//                        System.out.println("\tDatum: " + cal.getTime().toString());
//                        System.out.println("\tAusgestellt von: " + tempsigner.getIssuerX500Principal().toString());
//                        System.out.println("\tSeriennummer: " + tempsigner.getSerialNumber());
//                        if (!tmpEgovOID.equals("")) {
//                            System.out.println("\tVerwaltungseigenschaft: " + tmpEgovOID);
//                        }
//                        System.out.println("\n");
//                        System.out.println("\tDocument modified: " + !pk.verify());
////                Object fails[] = PdfPKCS7.verifyCertificates(pkc, kall, null, cal);
////                if (fails == null) {
////                    System.out.println("\tCertificates verified against the KeyStore");
////                } else {
////                    System.out.println("\tCertificate failed: " + fails[1]);
////                }
//                    }
//
//                //////
                } else {
                    signatureBlock = new Rectangle(0, 0, 0, 0); // fake definition
                }
                PdfSignatureAppearance sap = stp.getSignatureAppearance();
               
                /* 
                 * SHA2 implementation (inspired by itext reference implementation) 
                 */
                
                Calendar cal = Calendar.getInstance();              // date for signature
                Certificate[] chain = GetPKCS12.certificateChain;   // load complete certificate chain
                
                // atttributes needed for signature
                PdfDictionary dic = new PdfDictionary();
                dic.put(PdfName.FT, PdfName.SIG);
                dic.put(PdfName.FILTER, new PdfName("Adobe.PPKLite"));          // Acrobat standard for PKCS1 signing
                dic.put(PdfName.SUBFILTER, new PdfName("adbe.pkcs7.detached")); // all digets != SHA1 are "detached"
                dic.put(PdfName.M, new PdfDate(cal));  // add datum
                dic.put(PdfName.NAME, new PdfString(PdfPKCS7.getSubjectFields((X509Certificate)chain[0]).getField("CN"))); // obtain Common Name from Certificate
                sap.setCryptoDictionary(dic);
                HashMap exc = new HashMap();

                sap.setReason(signReason);              // set signing reason as set in GUI
                sap.setLocation(signLocation);          // set location as set in GUI
//                if (signText) {                             // some dead code ?                           
//                    sap.setVisibleSignature(signatureBlock,
//                            pages + 1, "PortableSigner");
//                }
                if (finalize) {                               // finalize if set in GUI
                    sap.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
                } else {
                    sap.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);
                }

                exc.put(PdfName.CONTENTS, new Integer(16386)); // ? some kind of placeholder for the detached signature, I guess
                sap.preClose(exc);

                // build the SHA2 digest
                PdfPKCS7 pk7 = new PdfPKCS7(GetPKCS12.privateKey, chain, null, "SHA-256", null, false);
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                byte buf[] = new byte[18192];               // XXX magic value seems to be dirty: placehoder for generated SHA2 digest

                InputStream inp = sap.getRangeStream();     // get the range covered by the digest
                messageDigest.update(IOUtils.toByteArray(inp));  // digest creation magic (loop through byte stream)
                byte[] hash = messageDigest.digest();       // copy the created digest to "magic placehoder"    
                
                // build the PKCS7 signature
                byte sh[] = pk7.getAuthenticatedAttributeBytes(hash, cal, null);
                pk7.update(sh, 0, sh.length);
                PdfDictionary dic2 = new PdfDictionary();
                byte sg[] = pk7.getEncodedPKCS7(hash, cal);
                int ESTIMATED_SIGNATURE_SIZE = 8192;                // XXX again a magic value ... would be nice to know if 
                byte[] out = new byte[ESTIMATED_SIGNATURE_SIZE];    //          size is sufficient in all cases 
                
                System.arraycopy(sg, 0, out, 0, sg.length);  // write the signature to the Contents placeholder
                dic2.put(PdfName.CONTENTS, new PdfString(out).setHexWriting(true));   // which was created above
                sap.close(dic2);   
                
                /*
                 *      SHA 2 signature done
                 */
                
                stp.close();
                
                /* MODIFY BY: Denis Torresan
                Main.setResult(
		                java.util.ResourceBundle.getBundle("net/pflaeging/PortableSigner/i18n").getString("IsGeneratedAndSigned"),
		                false,
		                "");
								*/
                
            } catch (Exception e) {
            	
            	/* MODIFY BY: Denis Torresan
                Main.setResult(
                        java.util.ResourceBundle.getBundle("net/pflaeging/PortableSigner/i18n").getString("ErrorWhileSigningFile"),
                        true,
                        e.getLocalizedMessage());
							*/
                
                /* 
                 * XXX Bug introduced with SHA2 patch: if this code is active, there is the following exception:
                 *    "Error while signing   Document already pre closed."
                 * this is a ghost error as document was created and is sane!
                 * workaround: remove the lines 
            	//throw new PDFSignerException(
            	//		java.util.ResourceBundle.getBundle("net/pflaeging/PortableSigner/i18n").getString("ErrorWhileSigningFile"),
                //        true,
                //         e.getLocalizedMessage() );
                 */
            }
            
            
        } catch (KeyStoreException kse) {
        	
        	/* MODIFY BY: Denis Torresan
            Main.setResult(java.util.ResourceBundle.getBundle("net/pflaeging/PortableSigner/i18n").getString("ErrorCreatingKeystore"),
                    true, kse.getLocalizedMessage());
            */
        	
        	throw new PDFSignerException(
        			java.util.ResourceBundle.getBundle("net/pflaeging/PortableSigner/i18n").getString("ErrorCreatingKeystore"),
                    true, kse.getLocalizedMessage() );
        	
        }
    }
}
