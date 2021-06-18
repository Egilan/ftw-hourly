import React from 'react';
import PropTypes from 'prop-types';
import classNames from 'classnames';

import css from './TermsOfService.module.css';

const TermsOfService = props => {
  const { rootClassName, className } = props;
  const classes = classNames(rootClassName || css.root, className);

  // prettier-ignore
  return (
    <div className={classes}>
      <p className={css.lastUpdated}>Päivitetty 26.5.2021</p>

      <p>
        LUETHAN NÄMÄ EHDOT HUOLELLISESTI ENNEN PALVELUMME TAI SIVUSTOMME KÄYTTÖÄ
      </p>

      <h2>1 Osapuolet</h2>
      <p>
        Näitä käyttöehtoja (myöh. "ehdot") sovelletaan palveluntarjoajaan, Weddi Oy:hyn (y-tunnus: ; myöh. Weddi), 
        sekä sivustoa käyttäviin henkilöihin. Käyttäessä Weddin palveluja, käyttäjä sitoutuu noudattamaan näitä ehtoja.
      </p>

      <h2>2 Palvelun käyttö</h2>
      <p>
        Weddi on verkkosivusto, jolla käyttäjä voi etsiä ja varata hääpalveluita ja juhlatiloja. 
        Palveluntarjoajat voivat listata omat palvelunsa ja tarjota niitä asiakkailleen. 
        Palvelu välittää maksut turvallisesti käyttäjältä palveluntarjoajalle.</p>
        <p>
        Lähettäessä kyselyn tai tarjouspyynnön sivustomme kautta, antamasi tiedot välitetään sille palveluntarjoajalle, 
        jolle olet kyselysi tai tarjouspyynnön kohdistanut.</p>
        <p>
        Palveluita sekä juhlatiloja koskevat varaukset, peruutukset, maksut, 
        mahdolliset reklamaatiot sekä kaikki muut toimenpiteet ja transaktiot tapahtuvat käyttäjän ja ko. palveluntarjoajan kesken. 
        Weddi ei toimi osapuolena käyttäjän ja palveluntarjoajan välisessä suhteessa, 
        vaan sopimussuhde syntyy aina kyseisen palveluntarjoajan ja käyttäjän välille. 
        Weddi toimii vain välittäjänä tiedoille, sopimukselle ja maksuille. 
        Weddi ei vastaa Weddin palveluiden kautta varatuista palveluista tai tiloista, vaan vastuu on aina kyseisellä palveluntarjoajalla.
      </p>

      <h2>3 Oikeudet ja velvollisuudet</h2>
      <p>
        Käyttäjä sitoutuu käyttämään Weddin palveluita hyvän tavan ja ehtojen mukaisesti. 
        Palveluiden käyttö edellyttää myös kaikkien soveltuvien lakien ja asetusten sekä Weddin mahdollisesti antamien palvelun käyttöön liittyvien ohjeiden noudattamista. 
        Lähettäessäsi kyselyn tai tarjouspyynnön kauttamme sitoudut antamaan meille ja palveluntarjoajalle ajantasaiset ja oikeelliset tiedot.</p>
        <p>
        Käyttäjä saa tämän sopimuksen mukaisen, rajoitetun, peruutettavissa olevan, ei-yksinomaisen käyttöoikeuden käyttää Weddin palveluita näiden ehtojen mukaisesti. 
        Käyttäjällä ei ole oikeutta käyttää Weddin palveluita muuhun kuin näissä käyttöehdoissa kuvattuihin tarkoituksiin.</p>
        <p>
        Käyttäjällä ei ole oikeutta muokata, kopioida, tallentaa, esittää julkisesti, jakaa tai siirtää Weddin palveluissa sijaitsevia tietoja muuta kuin pakottavien tekijänoikeuslakien sallimissa rajoissa.</p>
        <p>
        Käyttäjä ei myöskään saa käyttää palveluita siten, että käytöstä aiheutuisi vahinkoa tai häiriötä Weddille tai palveluntarjoajille. 
        Käyttäjä sitoutuu siihen, ettei se yritä vahingoittaa tai muutoin vaikeuttaa palveluita tai niiden käyttöä.

      </p>

      <h2>4 Weddi-palkkio</h2>
      <p>
        Weddi-palkkio on 5% tuotteen tai palvelun kokonaishinnasta ja se sisältyy ilmoitettuun hintaan ostosivuilla. Tämä palkkio mahdollistaa palvelun ylläpidon.
      </p>

      <h2>5 Peruutusoikeus</h2>
      <p>
        Tehdessä varauksen, asiakas sitoutuu maksamaan palvelun kokonaisuudessaan ja kommunikoimaan palveluntarjoajan kanssa kaikki tarvittavat tiedot, jotta tämä voi suorittaa palvelun. 
        Hyväksyessään palvelun varauksen, palveluntarjoaja sitoutuu tuottamaan palvelun kuvaamallaan tavalla, tarjouksessa esittämällään hinnalla.</p>
        <p>
        Mahdollisissa peruutustilanteissa käyttäjän tulee olla yhteydessä palveluntarjoajaan mahdollisimman pian sopiakseen, miten toimitaan. 
        Oli peruutuksen syy mikä tahansa, käyttäjän, eli asiakkaan toimesta tehdystä peruutuksesta, ei Weddi-palkkiota palauteta. 
        Lisäksi palveluntarjoaja on saattanut määritellä oman ns. varausmaksun, jonka se voi pidättää itsellään asiakkaan peruessa. 
        Mikäli palvelu ei vastaa kuvattua, joutuu asiakas neuvottelemaan palveluntarjoajan kanssa korvauksista tai hinnan alennuksista.</p>
        <p>
        Mikäli palveluntarjoaja onkin estynyt tuottamaan palvelun kuvaamallaan tavalla ja sopimus päätetään purkaa molempien osapuolien toimesta, Weddi-palkkio palautetaan kokonaisuudessaan.

      </p>

      <h2>6 Vastuu ja vastuunrajoitus</h2>
      <p>
        Weddi ei vastaa käyttäjälle mahdollisesti aiheutuvista vahingoista, ml. suorat, epäsuorat tai välilliset vahingot, 
        liittyen Weddin sivustoihin ja palveluihin tai niiden käyttöön tai käyttämättömyyteen, palveluntarjoajien tai muiden kolmansien osapuolten toimiin tai palveluihin tai mihin tahansa muuhun syyhyn. 
        Nämä vastuunrajoitukset ovat voimassa, vaikka Weddille tai sen edustajille olisi etukäteen ilmoitettu mahdollisista vahingosta, menetyksistä tai kustannuksista.</p>
        <p>
        Weddi tarjoaa palvelun sellaisena kuin se on. Vaikka Weddi pyrkii minimoimaan häiriöt, ei Weddi anna minkäänlaisia suoria tai epäsuoria takuita Weddin palveluiden käytöstä, 
        sivustoillamme tai palveluissamme sijaitsevista materiaaleista tai tiedoista kuten tietojen ajantasaisuudesta, virheettömyydestä, tietoturvasta, soveltuvuudesta tiettyyn käyttötarkoitukseen, 
        immateriaalioikeuksista tai muista asioista. Weddi ei vastaa käyttäjän Weddiin palveluiden välityksellä lähettämistä, lähettämättä taikka vastaanottamatta jääneistä viesteistä tai muista tiedoista.</p>
        <p>
        Weddillä on oikeus milloin tahansa muokata palveluaan ja muuttaa sitä esimerkiksi muuttamalla maksuttomia ominaisuuksia maksullisiksi sekä lopettaa tai keskeyttää palveluitaan tai niiden osia ilman ennakkovaroitusta.

      </p>

      <h2>7 Henkilötiedot ja evästeet</h2>
      <p>
        Weddin palvelujen käyttö edellyttää sitä, että käyttäjä on antanut palvelun käyttöä varten tarvittavat tiedot. Henkilötietojen keräämisen, käytön ja siirtämisen osalta sekä evästeistä ks. Tietosuojakäytäntömme.

      </p>

      <h2>8 Sopimuksen siirto</h2>
      <p>
        Weddillä on oikeus siirtää tämä sopimus sekä siitä johtuvat oikeudet ja velvoitteet milloin tahansa, osittain tai kokonaan kolmannelle osapuolelle ilman etukäteisilmoitusta.
      </p>

      <h2>9 Sovellettava laki</h2>
      <p>
        Weddin palveluiden käyttämiseen ja näihin ehtoihin sovelletaan Suomen lakia, lukuun ottamatta sen lainvalintasäännöksiä.</p>
        <p>
        Osapuolet pyrkivät ensisijaisesti ratkaisemaan erimielisyydet neuvotteluin ja hyvässä hengessä. Mikäli sovintoon ei päästä, kaikki Weddin palveluista ja niiden käytöstä sekä näistä ehdoista aiheutuvat riidat ratkaistaan Helsingin käräjäoikeudessa. Kuluttaja voi viedä erimielisyyden myös kuluttajariitalautakunnan ratkaistavaksi.
      </p>
    </div>
  );
};

TermsOfService.defaultProps = {
  rootClassName: null,
  className: null,
};

const { string } = PropTypes;

TermsOfService.propTypes = {
  rootClassName: string,
  className: string,
};

export default TermsOfService;
