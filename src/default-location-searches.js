import { types as sdkTypes } from './util/sdkLoader';

const { LatLng, LatLngBounds } = sdkTypes;

// An array of locations to show in the LocationAutocompleteInput when
// the input is in focus but the user hasn't typed in any search yet.
//
// Each item in the array should be an object with a unique `id` (String) and a
// `predictionPlace` (util.types.place) properties.
const defaultLocations = [
  {
    id: 'default-helsinki',
    predictionPlace: {
      address: 'Helsinki, Uudenmaan maakunta, Suomi',
      bounds: new LatLngBounds(
        new LatLng(60.37960431, 25.17705468),
        new LatLng(60.00650448, 24.69011268)
      ),
    },
  },
  {
    id: 'default-turku',
    predictionPlace: {
      address: 'Turku, Varsinais-Suomen maakunta, Suomi',
      bounds: new LatLngBounds(
        new LatLng(60.6655688, 22.56176223),
        new LatLng(60.26266406, 21.93796566)
      ),
    },
  },
  {
    id: 'default-tampere',
    predictionPlace: {
      address: 'Tampere, Pirkanmaan maakunta, Suomi',
      bounds: new LatLngBounds(
        new LatLng(61.77274519, 24.07749844),
        new LatLng(61.36274108, 23.42024484)
      ),
    },
  },
  {
    id: 'default-oulu',
    predictionPlace: {
      address: 'Oulu, Pohjois-Pohjanmaan maakunta, Suomi',
      bounds: new LatLngBounds(
        new LatLng(65.5687753, 26.31163393),
        new LatLng(64.5713489, 24.50536293)
      ),
    },
  },
];
export default defaultLocations;