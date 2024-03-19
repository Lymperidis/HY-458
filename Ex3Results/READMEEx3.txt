CSD4813 LYMPERIDIS LYMPERIS		



Ex1:Ο τροπος που λειτουργει ο κωδικας ειναι ο εξης :

Για την calculate:

1)Παιρνω αρχικα το input με hex , ανοιγω το pem file που εχει το μεσα το private key. 

2)Αρχικα κανω calculate to digital signature του μηνυματος κανοντας hash το μηνυμα επειτε μετατρεπω το 
το μηνυμα απο bytes σε integer υψωνω το μηνυμα στο private exponent (n)

3)ΕΠιστρεφω πισω σε bytes 

4)Επιστρεφω το signature σε bytes.


Για την verify : 

1)Μετατρεπω το signature σε integer


2)Verify μεσα το RSA χωρις padding 

3)Επιστρεφω την τιμη πισω σε bytes 


4)Hashing παλι (δεν εχει διαφορα)

5)Αν το hash_value == decrypted_signature_bytes τοτε ειτε θα ειναι true ή false



Ex2:
Μεσω της συναρτησεις εχω ενα n το οποιο ειναι ευαλωτω σε farmat factorization επειτα
με την isqrt και fermat functions βρισκω δυο αριθμους που ειναι factors του n και μετα 
φτιαχνω ενα private_key μεσω της RASPrivateNumber και μετα επιστρεφω το key.Τελος κανω 
save το private key στον φακελο.


Ex3:

Παιρνω ενα μηνυμα. Παιρνω ενα κλειδι το οποιον ειναι ευαλωτω σε fermat factorization 
το μετατρεπω σε bytes.Πειραζω το πρωτο byte και βαζω G κανω recover to private και για το
modify message.Φτιαχνω ενα signature με το private_key του modify message και το επιστρεφω
και το κανει το verify διοτι το Public key παραμενει ιδιο μονο το private key αλλαζει

To Integriy της τριαδας εχει παραβιαστει διοτι το integrity εξασφαλιζει οτι η πληροφορια
δεν εχει τροποποιηθει. Οταν επεξεργαζεσαι το μηνυμα χωρις εξουσιοδοτηση τοτε υπονομευει 
το integrity του μηνυματος. Μη εξουσιοδοτημενες αλλαγες μπορουν να οδηγησουν σε παραπλοηροφορηση,
ελλειψη εμπιστοσυνης και διαφορα θεματα ασφαλειας.




Ex4:Αυτο που γινεται σε αυτην την ασκηση ειναι ενα MIΤM attack. Αυτου του ειδος 
attack ειναι πολυ πιθανο να γινει σε ενα σημερινο browser.Μπορουν να γινουν σε διαφορες μορφες
οπως το intercept unecrypted traffic που με πλαστη πιστοποιηση ή να εκμεταλλευονται 
αδυναμιες σε πρωτοκολλα επικοινωνιας.Μπορουμε να προστατευουμε με τα πρωτοκολλα επικοινωνιας οπως 
SSL ή TLS που προστατευουν τα δεδομενα στο transit. Αλλοι τροποι ειναι CA που ειναι third parties τα οποια 
κανουν validate τα digital certificates.



Ex5:

Η λογικη της ασκησης ειναι η εξης :

Δημιουργειται ενα τυχαια μηνυμα 256 bits το οποιο γινεται hash. Μετα παιρνω ενα τυχαια αριθμος 
ο οποιος ειναι σχετικα πρωτος αριθμος ετσι ωστε να εχει αντιστροφο στο modulo.Δημιουργω το 
blind message υψωνοντας τον τυχαια αριθμο r στην δυναμη του e(public exponent) και τελος πολλαπλασιαζοντας 
το με το hash του message και παιρνοντας το αποτελεσμα ολου αυτου του modulo με το Ν.

Παιρνω το blinded signature μεσω της sign του Signer(m_prime).Υπολογιζω το unblinded message 
του μηνυματος πολλαπλασιαζοντας το multiplicative inverse του r modulo N επι το blind signature 
Αυτο δινει το unblinded signature του μηνυματος.Επεστρεψε το μηνυμα και το signature.


Για να ελεγξω οτι ειναι verified το signature σε ενα message θα υψωσω το signature στο public key 
και στο modulo n(public modulus).Αυτο ουσιαστικα αντιστρεφει την διαδικασια υπογραφης 
και παιρνουμε πισω το hashed message.

Τεσταρω καθε φορα αλλαζω το μηνυμα και το κανω verified . Το ιδιο κανω και για το signature 
Αν δεν ταιριαζει το signature με το μηνυμα πεταει false.





Ex6:Σε αυτην την ασκηση υπολογιζουμε μεσα απο το power trace ενος ciphertext τα bits ενος μηνυματος.
Με αυτον τον τροπο μπορουμε να υπολογισουμε το private exponent του private key και επειτα να αποκρυπτογραφησουμε το μηνυμα.
H decrypt του victim κανει simulate ενα decryption method και δειχνει τα power usage του επεξεργαστη. Μεσω απο αυτο αναλυοντας τα
ανεβοκατεβασματα μπορουμε να καταλαβουμε τα bits του exponent. Αν διαβαζουμε ενα high voltage και μετα ακολουθησει idle χωρις να ακολουθησει ξανα
ενα high voltage σημαινει οτι εχουμε μονο squaring που αυτο σημαινει οτι το bit ειναι 0. Αν μετα απο high voltage εχουμε idle και μετα
ξανα εχουμε high voltage σημαινει οτι εχουμε squaring και multiplication αρα το bit 1 . Αρα σιγα σιγα κανουμε construct το exponent.
Επειτε φτιαχουμε το private και απο το reconstruct private key μεσω του public key και του exponent d.




