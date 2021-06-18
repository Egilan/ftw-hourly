import React from 'react';
import PropTypes from 'prop-types';
import classNames from 'classnames';

import css from './PrivacyPolicy.module.css';

const PrivacyPolicy = props => {
  const { rootClassName, className } = props;
  const classes = classNames(rootClassName || css.root, className);

  // prettier-ignore
  return (
    <div className={classes}>
      <p className={css.lastUpdated}>Päivitetty 26.5.2021</p>

      <p>
        Me Weddillä arvostamme yksityisyyttäsi ja pyrimme tarjoamaan sinulle turvallisen ja varman käyttökokemuksen. 
        Rekisterinpitäjä, Weddi Oy (y-tunnus, jäljempänä “Weddi”) on sitoutunut suojaamaan palvelujensa ja sivustojensa käyttäjien yksityisyyttä, 
        noudattaen toiminnassaan soveltuvia tietosuoja- ja muita lakeja sekä hyviä tietosuojaperiaatteita. 
        Tässä tietosuojaselosteessa kuvataan Weddin henkilötietojen keräämistä ja käsittelyä koskevat periaatteet 
        ja sitä sovelletaan Weddin sivustojen kautta sekä Weddin palvelun käytön tai muun toiminnan yhteydessä kerättyjen henkilötietojen käsittelyyn.
      </p>
      <p>
        Weddiin kuuluu tällä hetkellä ainoastaan weddi.fi-sivusto. Sivustomme voi sisältää linkkejä kolmansien osapuolten sivustoille tai palveluihin, jotka vastaavat omalta osaltaan tietosuojaperiaatteistaan. 
        Tämä tietosuojaseloste ei sovellu tällaisten kolmansien sivustojen tai palveluiden käyttöön.
      </p>
      <p> 
        Mikäli et hyväksy henkilötietojesi käsittelyä tämän Tietosuojaselosteen mukaisesti, älä käytä Weddin sivustoja tai palveluja.
      </p>

      <h2>1. Mitä tietoa keräämme?</h2>
      <p>
      Weddi voi kerätä käyttäjistään tässä tietosuojaselosteessa selostettujen käyttötarkoitusten kannalta tarpeellisia tietoja. Käyttötarkoitus määrittää, minkälaista tietoa käyttäjistä kerätään eri tilanteissa.
      </p>
      <p>
      Henkilötietojasi voidaan kerätä palveluidemme käytön yhteydessä, esimerkiksi lähettäessäsi viestejä Weddin sivuston kautta, 
      jatkaessasi Weddin kautta keskustelua Weddin yhteistyökumppaneiden kanssa, sekä kilpailujen, kampanjoiden tai tutkimusten yhteydessä sekä muutoin asioidessasi kanssamme.
      </p>
      <p>
      Weddi kerää muun muassa alla mainittuihin ryhmiin kuuluvia henkilötietoja. Tiedot kerätään pääasiassa käyttäjältä itseltään Weddin sivustojen ja palveluiden käytön yhteydessä.
      </p>
      <p>
      Henkilötietojasi voidaan kerätä myös muualta kuin suoraan sinulta, esimerkiksi kolmansien osapuolten ylläpitämistä rekistereistä kuten 
      Digi- ja väestötietovirastosta ja Suomen Asiakkuusmarkkinointiliiton ylläpitämästä kieltorekisteristä sekä muista vastaavista rekistereistä. 
      Jotta voimme tarjota palveluitamme, Weddi käyttää myös ulkopuolisia tahoja kuten IT-palveluntarjoajia mm. tietojen tallentamiseen ja hallinnointiin. 
      Saatamme myös käyttää ulkopuolisia palveluntarjoajia mm. asiakasseurantaan ja markkinointiin esimerkiksi hyödyntämällä kolmansien osapuolten markkinointityökaluja alla tarkemmin kuvatuin tavoin.
      </p>
      <h3>1.1. Weddille antamasi tiedot</h3>
      <p>
      Saatamme kysyä sinulta eri palvelujen ja sivustojen käytön yhteydessä tietoja, joita voit halutessasi antaa Weddille. 
      Osa tiedoista voi olla pakollisia palvelun käytön mahdollistamiseksi. Lisäksi käsittelemme myös itse antamiasi tietoja.
      </p>
      <p>
      Tällaisia tietoja voivat olla esim.:
      </p>
      <ul className={css.privacyPolicyList}>
        <li>  
        Perustiedot, kuten etu- ja sukunimi, osoite, puhelinnumero, sähköpostiosoite
        </li>
        <li>  
        Salasana ja nimimerkki
        </li>
        <li>  
        Asiakkuuteen liittyvät tiedot, kuten palveluissa tekemäsi tai niiden avulla tehdyt tarjouspyynnöt, tilaukset ja ostot 
        </li>
        <li>  
        Asiakaspalautteet
        </li>
        <li>  
        Häihisi liittyvät tiedot
        </li>
        <li>  
        Kommunikaatio Weddin yhteistyökumppaneiden kanssa häihisi liittyen
        </li>
      </ul>
      
      <p>
      Hääpalveluntarjoajilta keräämme lisäksi seuraavia tietoja:
      </p>
      <ul className={css.privacyPolicyList}>
        <li>  
        Yrityksen nimi, y-tunnus, ALV-numero, toimiala ja yhteystiedot
        </li>
      </ul>
      <p>
      Lisäksi voimme kerätä muita yhteystietoja, joita tarvitaan mm. tuotteiden ja palvelujen toimittamiseen, asiakasviestintään ja käyttäjien tunnistamiseen. 
      Voimme kerätä myös ns. demografiatietoja esim. ikä, sukupuoli, kieli, asuinaluetta kuvaavat tiedot, sekä mieltymyksiäsi, toivomuksiasi ja 
      tietoja antamistasi suostumuksista sekä muita vastaavia tietoja, joita tarvitsemme mm. tuotteiden ja palvelujen kehittämiseen ja palvelujemme kohdentamiseen.
      </p>
      <p>
      Jotkin palvelumme ominaisuudet voivat myös olla luonteeltaan sellaisia, että niissä julkaistaan käyttäjien henkilötietoja. 
      Tällaisia ovat esimerkiksi ominaisuudet, joiden avulla käyttäjä julkaisee omia sisältöjään. Tällöin käyttäjä päättää itse, millaisia tietoja hän luovuttaa ja julkaisee.
      </p>
      

      <h3>1.2. Palvelujen käytöstä havainnoidut ja johdetut tiedot</h3>
      <p>
      Saatamme automaattisesti kerätä sinusta ja Weddin palvelujen käytöstä seuraavia tietoja mm. evästeiden avulla:
      </p>
      <ul className={css.privacyPolicyList}>
        <li>  
        Verkkopalvelujen analytiikkajärjestelmien keräämät tiedot (ks. Käyttäjän tunnistus ja evästeiden käyttö)
        </li>
        <li>  
        Asiakasviestinnän tiedot, esim. tiedot linkkien klikkauksista
        </li>
        <li>  
        Verkkosivu, jolta on siirrytty Weddin verkkosivulle
        </li>
        <li>  
        Laitetunnisteet, kuten päätelaitteen malli ja yksilöllinen laite- ja/tai evästetunniste
        </li>
        <li>  
        Tiedonkeruun kanava: internetselain, mobiiliselain, sovellus sekä selaimen versio
        </li>
        <li>  
        IP-osoite
        </li>
        <li>  
        Päätelaitteen käyttöjärjestelmä
        </li>
        <li>  
        Istuntotunniste, istunnon aika ja kesto
        </li>
      </ul>
      <p>
      Käyttäjän niin salliessa, keräämme myös sijaintitietoja, joita käytetään pääosin vain hakujen suorittamiseen. 
      </p>
      <p>
      Vaikka Weddin sivustoja voi useimmiten selailla ilman, että sinun täytyy rekisteröityä tai muuten tunnistautua, selaimesi toimittaa Weddille tiettyjä tietoja, 
      esimerkiksi käyttämäsi IP-osoitteen, selailun ajankohdan, miltä sivuilta olet tulossa, millä sivuilla vierailet, mitä linkkejä käytät ja mitä sisältöjä olet katsonut. 
      Weddin sivustojen, tuotteiden ja palvelujen käytön yhteydessä voi syntyä myös muuta teknisluonteista tietoa, jota keräämme. Esimerkiksi liittymäsi puhelinnumero, 
      palvelun käyttöajankohta ja muita vastaavia palvelun käyttöä kuvaavia tietoja voi siirtyä Weddille osana normaalia viestin välitystä. 
      Weddi käyttää sivustoillaan evästeitä ("cookie"), joiden käytöstä annetaan lisätietoja alempana kohdassa "Käyttäjän tunnistus ja evästeiden käyttö".
      </p>
      <h3>1.3. Asiakkuuteen ja sopimussuhteeseen liittyvät tiedot</h3>
      <p>
      Keräämme tietoja asiakkuuteen ja sopimussuhteeseen liittyvistä asioista, esimerkiksi tilaamiisi ja/tai käyttämisiisi palveluihin, sopimuksiin, yhteydenottoihin, 
      asiakasvalituksiin, sekä muiden palveluiden tarjontaan ja käyttöön liittyviä tietoja. Keräämme myös tuotteiden ja palvelujen maksamiseen ja laskutukseen liittyviä tietoja, 
      kuten laskutusosoite ja luottokorttitiedot, sekä luottotietojen tarkastamiseen liittyviä tietoja ja muita vastaavia taloudellisia tietoja. 
      Voimme myös nauhoittaa asiakaspalvelupuheluja ja kerätä muita sinun ja Weddin, sekä sinun ja yhteistyökumppaniemme väliseen kanssakäymiseen liittyvää tietoa.
      </p>
      
      <h2>2. Miksi käsittelemme henkilötietoja ja millä perusteilla?</h2>
      <p>
      Henkilötietojen käsittelyn ensisijaisena perusteena on Weddin palvelujen käyttämiseen liittyvä, käyttäjän ja Weddin välisen sopimussuhteen täytäntöönpano ja mahdollistaminen, 
      oikeutettu etu, käyttäjän suostumus tai lakisääteinen velvoite.
      </p>
      <p>
      Käsittely asiakassuhteiden hoitamiseen, palvelujen käyttämiseen ja sen ja liiketoiminnan hallintaan sekä niiden markkinointiin 
      ja niistä tiedottamiseen perustuu sopimussuhteeseen tai Weddin oikeutettuun etuun. Oikeutetulla edulla tarkoitetaan rekisterinpitäjän toimintaan olennaisesti liittyvää käsittelyä, 
      jonka käyttäjä voi kohtuudella olettaa kuuluvan sen toimintaan. Tällainen oikeutettu etu voi olla esimerkiksi hyvän asiakassuhteen säilyttäminen, 
      jotta Weddi voi tarjota käyttäjilleen entistä parempaa palvelua ja kehittää palveluitaan tai kun Weddin ja käyttäjän välillä on muu asianmukainen suhde.
      </p>
      <p>
      Markkinointi ja mainonta, kuten sähköinen suoramarkkinointi henkilökohtaisiin yksityisiin henkilötietoihin perustuu suostumukseen. 
      Suoramarkkinointia voidaan myös harjoittaa ilman suostumusta tilanteissa, joissa laki sen sallii. 
      Markkinointi ja mainonta voi myös tietyissä tapauksissa perustua oikeutettuun etuun (esim. B-2-B-markkinointi tai Weddin järjestämiä tapahtumia koskevat yhteydenotot).
      </p>
      <p>
      Käsittelemällä henkilötietoja pyrimme myös parantamaan ja varmistamaan palveluidemme turvallisuuden ja väärinkäytösten estämisen sekä selvittämisen. Nämä perustuvat lakisääteiseen velvollisuuteemme.
      </p>
      <p>
      Käsittelemme henkilötietojasi alla määriteltyihin yhteen tai useampiin tarkoituksiin liittyen.
      </p>
      <h3>2.1. Tuotteiden ja palvelujen tarjoaminen ja asiakassuhteen ylläpitäminen</h3>
      <p>
      Henkilötietojasi voidaan käyttää kyselyiden ja muiden yhteydenottojen hallinnointiin palvelun käytön mahdollistamiseksi, sopimusten täytäntöönpanoon tai valmisteluun 
      ja muiden vastaavien velvoitteiden mahdollistamiseksi sekä pyyntöihisi ja kysymyksiisi vastaamiseen. Henkilötietojasi voidaan kerätä myös käyttäjien tunnistamiseen, 
      tuotteiden ja palvelujen toteuttamiseen, viestien välitykseen, tietoturvasta huolehtimiseen sekä väärinkäytösten ehkäisyyn ja tutkintaan, lain sallimissa rajoissa
      </p>
      <h3>2.2. Tuotteiden ja palvelujen kehittäminen</h3>
      <p>
      Henkilötietojasi voidaan käyttää Weddin tuotteiden, palvelujen ja liiketoiminnan kehittämiseen sekä sivustojemme käyttämisen seurantaan ja optimointiin. 
      Henkilötietojasi voidaan käyttää myös tuotteittemme ja palvelujemme kohdentamiseen, esimerkiksi voidaksemme näyttää sinulle räätälöityjä sisältöjä. 
      Voimme myös tehdä tuotteiden ja palvelujen kehittämisen edellyttämiä tilastoja ja yhdistää eri tuotteiden ja palvelujen yhteydessä kerättyjä tietoja. 
      Pyrimme mahdollisuuksien mukaan käyttämään tilastollisia ja muita vastaavia tietoja, joista yksittäistä käyttäjää ei voida tunnistaa.
      </p>
      <h3>2.3. Asiakasviestintä ja markkinointi</h3>
      <p>
      Henkilötietojasi voidaan käyttää lain sallimissa rajoissa Weddin ja sen yhteistyökumppanien ja muiden vastaavien toimijoiden tuotteiden ja palvelujen markkinointiin, 
      uutiskirjetilauksiin, sähköiseen ja muuhun suoramarkkinointiin, mielipide- ja markkinatutkimuksiin sekä asiakasviestintään, 
      esimerkiksi informoidaksemme sinua tuotteisiimme ja palveluihimme liittyvistä asioista. Voimme myös tehdä asiakastyytyväisyyttä koskevia ja vastaavia tutkimuksia.
      </p>
      <p>
      Teemme lisäksi kohdennettua markkinointia, jonka yhteydessä voimme suorittaa myös käyttäjien profilointia, jotta voimme tarjota sinua kiinnostavia palveluita esimerkiksi 
      aiemman käyttäytymisesi tai asiakastietoihin tallennettujen tietojen perusteella. Käyttämiemme muiden osapuolten palveluista ks. kohta “Kolmansien osapuolten palvelut”.
      </p>
      <h3>Alaikäisiä koskevien tietojen käsittely</h3>
      <p>
      Koska emme voi todentaa käyttäjien ikää, myös alle 18-vuotiaita koskevia tietoja saattaa päätyä rekisteriimme, vaikka emme näitä tarkoituksella kerääkään.
      </p>
      
      <h2>3. Luovutammeko henkilötietoja?</h2>
      <p>
      Weddi ei myy, lainaa tai muutoin luovuta henkilötietojasi muuten kuin tässä tietosuojaselosteessa  mainituissa tilanteissa.
      </p>
      <h3>3.1. Yhteistyökumppanit ja kolmannet osapuolet</h3>
      <p>
      Lähettäessäsi kyselyn Weddin kautta siirrämme antamasi henkilötiedot yhteistyökumppaneillemme eli tiloille ja muille Weddin palveluntarjoajille tai 
      kumppaneille palvelun käytön ja kommunikaation sekä muun yhteistyön mahdollistamiseksi yhteistyökumppaneidemme kanssa. 
      Luovutamme tiedot vain niille yhteistyökumppaneille, joille olet kohdistanut kyselysi. 
      Pyydämme sinua tutustumaan huolellisesti kyseisten yhteistyökumppanien omiin tietosuojakäytäntöihin. 
      Käytämme myös kolmansien osapuolten palveluita esim. analysointitarkoituksiin. Ks. tarkemmin kohta “Kolmansien osapuolten palvelut” alla.
      </p>
      <h3>3.2. Alihankkijat</h3>
      <p>
      Henkilötietojasi voidaan luovuttaa Weddin alihankkijoille siinä määrin, kun ne osallistuvat tässä Tietosuojakäytännössä kuvattujen käyttötarkoitusten toteuttamiseen.
      </p>
      <h3>3.3. Kansainväliset tietojen siirrot</h3>
      <p>
      Weddi pyrkii toteuttamaan palvelut ja käsittelemään henkilötietosi ensisijaisesti EU- tai ETA-alueella sijaitsevia toimijoita ja palveluja hyödyntäen. 
      Weddin palveluja saatetaan kuitenkin joissakin tapauksissa toteuttaa myös muualla sijaitsevia toimijoita, 
      palveluja ja palvelimia käyttäen ja tällöin henkilötietojasi saatetaan siirtää eri maiden välillä. 
      Tällaiset siirrot voivat sisältää henkilötietojen luovutuksia EU- tai ETA-alueen ulkopuolelle sellaisiin maihin, 
      joiden henkilötietojen käsittelyä koskeva lainsäädäntö poikkeaa Suomen lain vaatimuksista, esimerkiksi Yhdysvaltoihin. 
      Weddi huolehtii tällöinkin henkilötietojesi suojan riittävästä tasosta muun muassa sopimalla henkilötietojen käsittelyyn liittyvistä asioista lainsäädännön edellyttämällä tavalla, 
      esimerkiksi EU:n komission hyväksymiä mallisopimuslausekkeita käyttäen ja muutenkin siten, että henkilötietojen käsittely tapahtuu tämän tietosuojaselosteen mukaisesti.
      </p>
      <h3>3.4. Pakottavan lainsäädännön edellyttämät luovutukset</h3>
      <p>
      Henkilötietojasi voidaan luovuttaa lakiin perustuvan, esimerkiksi viranomaisen esittämän vaatimuksen perusteella.
      </p>
      <h3>3.5. Yritysjärjestelyt ja konserni</h3>
      <p>
      Mikäli Weddi on osallisena yritysjärjestelyssä, kuten liiketoimintansa tai sen osan myynnissä, 
      voidaan kyseiseen liiketoimintaan liittyviä henkilötietoja siirtää liiketoiminnan mukana uudelle omistajalle. 
      Weddi voi myös luovuttaa tietoja konserninsa sisällä toisille konserniyhtiöille.
      </p>
      
      <h2>4. Miten huolehdimme tietojen ajantasaisuudesta?</h2>
      <p>
      Pyrimme kohtuullisin keinoin pitämään hallussamme olevat henkilötiedot oikeellisina poistamalla tarpeettomia tietoja sekä päivittämällä vanhentuneita tietoja. 
      Käyttäjä sitoutuu olemaan toimittamatta Weddille virheelliseksi tietämäänsä tietoa.
      </p>
      <p>
      Jotkin Weddin palvelut tai niiden osat voivat mahdollistaa sen, että käyttäjä hallinnoi ja pitää ajan tasalla itse omia henkilötietojaan.
      </p>
      
      <h2>5. Mitä teemme suojataksemme henkilötietojasi?</h2>
      <p>
      Kaikkeen henkilötietojen luovuttamiseen liittyy riskejä eikä mikään tekniikka tai prosessi ole täysin turvallinen. 
      Weddi pyrkii käyttämään asianmukaisia teknisiä ja organisatorisia keinoja henkilötietojen suojaamiseksi oikeudetonta pääsyä, luovuttamista ja muuta oikeudetonta käsittelyä vastaan, 
      ottaen huomioon tietojen luonteen, tekniset mahdollisuudet tietojen suojaamiseen, tietoihin kohdistuvan uhkan sekä tietojen suojaamisen kustannukset.
      </p>
      <p>
      Tällaisia keinoja voivat olla mm. palomuurien, salaustekniikoiden, turvallisten laitetilojen käyttö, kulunvalvonta, 
      rajoitettu käyttöoikeuksien myöntäminen ja käytön valvonta, henkilötietojen käsittelyyn osallistuvien henkilöiden ohjeistaminen, 
      alihankkijoiden huolellinen valinta sekä sopimuksellisten ja muiden vastaavien keinojen käyttö. 
      Käytämme standardien mukaisia tekniikoita liiketapahtumiemme luottamuksellisuuden turvaamiseksi.
      </p>
      
      <h2>6. Käyttäjän tunnistus ja evästeiden käyttö</h2>
      <p>
      Weddi voi käyttää sivustoillaan evästeitä eli "cookieta". Evästeet ovat pieniä tiedostoja, jotka lähetetään päätelaitteeseesi sivustoltamme, 
      ja joiden avulla tyypillisesti kerätään tiettyjä päätelaitetta koskevia tietoja, esimerkiksi käyttäjän IP-osoite, 
      päätelaitteen käyttöjärjestelmän tietoja, selaimen tyyppi ja tieto siitä, miltä sivustolta käyttäjä on tulossa Weddin -sivustoille. 
      Evästeiden käyttö mahdollistaa käyttäjille tiettyjä palveluja: esimerkiksi käyttäjän täytyy syöttää salasanansa vain kerran istunnon aikana tai käyttäjän ei tarvitse täyttää ostoskoriaan uudestaan, 
      jos ostotapahtuma jostain syystä keskeytyy. Evästeitä käytetään myös sivustomme liikenteen analysointiin, palvelujemme kehittämiseksi, 
      käyttäjäkokemuksen kehittämiseksi sekä markkinointitarkoituksiin kuten kohdennettuun markkinointiin.
      </p>
      <p>
      Voimme käyttää myös ns. web beaconeja joidenkin sivustojemme yhteydessä. Emme käytä web beaconeja yksittäisten käyttäjien tunnistamiseen, 
      vaan vain sivustojemme kehittämiseen. Web beaconit ovat tyypillisesti sivustolle sijoitettavia graafisia kuvia, joiden avulla voidaan kerätä tietoja sivuston käytöstä. 
      Tyypillisesti web beaconit eivät tuota muuta informaatiota, kuin mitä käyttäjän selain toimittaa palveluntarjoajalle osana palvelujen käyttöä. 
      Niiden avulla voidaan myös analysoida evästeitä. Jos evästeiden käyttö on estetty, web beacon ei voi seurata käyttäjän toimintaa, mutta voi edelleen kerätä selaimesi tuottamaa tietoa.
      </p>
      <p>
      Mikäli et halua vastaanottaa evästeitä tai haluat tulla informoiduksi niistä, voit muuttaa selaimesi asetuksia vastaavasti, mikäli selaimesi tämän mahdollistaa. 
      Evästeiden käytön estäminen voi kuitenkin johtaa siihen, että sivuston tai palvelun kaikki ominaisuudet eivät ole käytettävissäsi. 
      Joidenkin palveluntarjoajien sivustot, joihin Weddin sivustolla on linkki, voivat myös käyttää evästeitä tai web beaconeja. Weddilla ei ole pääsyä tai kontrollia tällaisiin evästeisiin.
      </p>
      
      <h2>7. Kolmansien osapuolten palvelut</h2>
      <p>
      Weddi käyttää kolmansien osapuolten verkkoanalyysi- ja seurantatyökaluja ja muita menetelmiä, ml. automaattisia tiedonkeruutyökaluja 
      esimerkiksi kerätäksemme tietoa käyttäytymisestäsi Weddin sivustoilla ja vuorovaikutuksestasi kanssamme. 
      Tällaisia palveluita ovat esimerkiksi käyttämämme verkkotyökalut, Google Analytics, Google Ads, Mixpanel, Facebook Business Manager ja Microsoft Ads. 
      Kerättyjä tietoja käytetään pääsääntöisesti tilastointi-, seuranta-, analysointi-, kohderyhmä- 
      ja markkinointitarkoituksiin sekä palveluiden ja liiketoiminnan kehittämiseen. Tietoja voidaan käyttää myös nk. profilointiin.
      </p>
      <p>
      Nämä kolmansien osapuolten palvelut hyödyntävät evästeitä ja/tai web beaconeja käyttäjien ja heidän käyttäytymisensä analysoimiseksi 
      ja mainonnan kohdentamiseksi myös Weddin ulkopuolisilla sivustoilla. Lisäksi ne saattavat hyödyntää myös muita henkilötietoja esimerkiksi markkinointitarkoituksiin.
      </p>
      <p>
      Käytämme myös kolmansien osapuolten palveluita markkinointi- ja muihin tarkoituksiin, kuten esimerkiksi ulkopuolisia sähköpostipalveluntarjoajia, jotka käsittelevät henkilötietoja omien käytäntöjensä mukaisesti.
      </p>
      <p>
      Saatamme myös hyödyntää kolmansien osapuolten tarjoamia nk. push-notifikaatiota, joilla käyttäjille lähetetään notifikaatioita ja muistutuksia käyttämällesi laitteelle ja selaimelle, edellyttäen, 
      että olet antanut hyväksyntäsi näiden notifikaatioiden vastaanottamiselle. Voit hallinnoida push-notifikaatioita ko. palveluntarjoajan tai laitteesi asetusten kautta.
      </p>
      
      <h2>8. Kuinka kauan säilytämme tietojasi?</h2>
      <p>
      Säilytämme tietojasi voimassa olevan lainsäädännön mukaisesti ja vain niin kauan, kuin on tarpeen tässä Tietosuojakäytännössä määriteltyjen tarkoitusten toteuttamiseksi. 
      Kun henkilötietojesi käsittelyperuste on päättynyt, poistamme henkilötietosi kohtuullisen ajan kuluessa.
      </p>
      <p>
      Huomioithan, että jotkut Weddin palvelut saattavat sisältää julkisia, vuorovaikutteisia ja viestinnällisiä ominaisuuksia, kuten kommentti- ja arvosteluosioita tai keskustelupalstoja, 
      jolloin tuottamasi sisältö voi jäädä näihin näkyviin myös sen jälkeen, kun olet lopettanut rekisteröimäsi käyttäjätunnuksen tai kun käyttäjä- tai asiakassuhde päättyy.
      </p>
      
      <h2>9. Mitkä ovat oikeutesi?</h2>
      <p>
      Sinulla on sovellettavaan tietosuojalainsäädäntöön perustuvia oikeuksia, joita käsittelemme tarkemmin alla. 
      Jos haluat hyödyntää oikeuksiasi, voit olla meihin yhteydessä tämän Tietosuojaselosteen lopussa olevien yhteystietojen kautta. 
      Sinulla on, lain sallimissa puitteissa, oikeus:
      </p>
      <ul className={css.privacyPolicyList}>
        <li>päästä käsiksi henkilötietoihisi ja tarkastaa, mitä tietoja olemme sinusta keränneet</li>
        <li>vaatia virheellisen, tarpeettoman, puutteellisen tai vanhentuneen henkilötiedon korjaamista tai poistamista</li>
        <li>pyytää henkilötietojen käsittelyn rajoittamista tietyin edellytyksin</li>
        <li>tulla unohdetuksi ja saada henkilötietosi poistetuksi edellyttäen, että ko. tietoja ei enää tarvita siihen tarkoitukseen, jota varten ne kerättiin</li>
        <li>vastustaa henkilötietojesi käsittelyä oikeutettuun etuun perustuen</li>
        <li>pyytää henkilötietojesi siirtämistä</li>
      </ul>
      <p>
      Huomaathan, että meillä voi tietyissä tilanteissa olla lakiin perustuvia velvoitteita tai niihin perustuva oikeus huomattavan painavan syyn muodossa henkilötietojen käsittelemiseksi tai säilyttämiseksi 
      (esim. oikeutettu etu, joka syrjäyttää rekisteröidyn intressit). Lisäksi, mikäli tarvitsemme tietoja oikeusvaateen liittyen, tietojen käsittelyä on sallittua jatkaa.
      </p>
      <p>
      Voit myös, silloin kun henkilötietojen käsittely perustuu suostumukseen, peruuttaa suostumuksesi ja siten kieltää Weddita käsittelemästä itseäsi koskevia tietoja esim. sähköiseen suoramainontaan. 
      Voit peruuttaa suostumuksesi ottamalla meihin yhteyttä alla mainittujen yhteystietojen kautta tai, kun kyse on uutiskirjeestämme, peruuttamalla uutiskirje “Unsubscribe”-kohdan kautta.
      </p>
      <p>
      Voit myös erikseen aina kieltää sähköisen suoramarkkinoinnin sekä profiloinnin.
      </p>
      <p>
      Toistuvista tietopyynnöistä saatamme joutua pyytämään kohtuullisen korvauksen kulujen kattamiseksi.
      </p>
      <p>
      Sinulla on myös oikeus tehdä valitus tietosuojavalvontaviranomaiselle, mikäli katsot, että henkilötietojasi on käsitelty voimassa olevan lainsäädännön vastaisesti.
      </p>
      <h2>10. Muutokset tähän Tietosuojaselosteeseen</h2>
      <p>
      Weddi kehittää jatkuvasti palvelujaan ja voi tehdä ajoittain muutoksia tähän Tietosuojaselosteeseen ilman etukäteisilmoitusta. 
      Jos tätä Tietosuojaselostetta muutetaan olennaisesti, Weddi ilmoittaa asiasta tämän Tietosuojaselosteen alussa tai muutoin sivustollaan. 
      Suosittelemme tutustumaan tähän Tietosuojaselosteeseen säännöllisesti.
      </p>
      
      <h2>11. Kuka on rekisterinpitäjä ja mihin voin ottaa yhteyttä?</h2>
      <p>
      Henkilötietojesi rekisterinpitäjänä toimii Weddi Oy, osoitteessa Uuno Kailaan katu 5 D 108, 02600 Espoo.
      </p>
      <p>
      Henkilötietojen keräämiseen ja käyttöön liittyvissä asioissa voit ottaa yhteyttä sähköpostitse osoitteeseen privacy@weddi.fi.
      </p>
      <p>
      Huomioithan, että voimme tietoturvasyistä joutua varmistamaan henkilöllisyytesi ennen pyyntösi täyttämistä.
      </p>
    </div>
  );
};

PrivacyPolicy.defaultProps = {
  rootClassName: null,
  className: null,
};

const { string } = PropTypes;

PrivacyPolicy.propTypes = {
  rootClassName: string,
  className: string,
};

export default PrivacyPolicy;
